package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

type ObjectServer struct {
	driveRoot      string
	hashPathPrefix string
	hashPathSuffix string
	checkMounts    bool
	disableFsync   bool
	asyncCleanup   bool
	allowedHeaders map[string]bool
	logger         *syslog.Writer
}

// ResponseWriter that saves its status - used for logging.

type SwiftWriter struct {
	http.ResponseWriter
	Status int
}

func (w *SwiftWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.Status = status
}

// http.Request that also contains swift-specific info about the request

type SwiftRequest struct {
	*http.Request
	Start time.Time
}

// request handlers

func (server ObjectServer) ObjGetHandler(writer *SwiftWriter, request *SwiftRequest, vars map[string]string) {
	headers := writer.Header()
	hashDir, err := ObjHashDir(vars, server)
	if err != nil {
		http.Error(writer, "Insufficent Storage", 507)
		return
	}
	// TODO: do proper logic, .meta files...
	dataFile := PrimaryFile(hashDir)
	if dataFile == "" || strings.HasSuffix(dataFile, ".ts") {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	file, err := os.Open(fmt.Sprintf("%s/%s", hashDir, dataFile))
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	defer file.Close()
	metadata, _ := ReadMetadataFd(int(file.Fd()))

	if deleteAt, ok := metadata["X-Delete-At"].(string); ok {
		if deleteTime, err := ParseDate(deleteAt); err == nil && deleteTime.Before(time.Now()) {
			http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
	}

	lastModified, err := ParseDate(metadata["X-Timestamp"].(string))
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	lastModifiedHeader := lastModified
	if lastModified.Nanosecond() > 0 { // for some reason, Last-Modified is ceil(X-Timestamp)
		lastModifiedHeader = lastModified.Truncate(time.Second).Add(time.Second)
	}
	headers.Set("Last-Modified", lastModifiedHeader.Format(time.RFC1123))
	headers.Set("ETag", fmt.Sprintf("\"%s\"", metadata["ETag"].(string)))
	headers.Set("X-Timestamp", metadata["X-Timestamp"].(string))
	for key, value := range metadata {
		if allowed, ok := server.allowedHeaders[key.(string)]; (ok && allowed) || strings.HasPrefix(key.(string), "X-Object-Meta-") {
			headers.Set(key.(string), value.(string))
		}
	}

	if im := request.Header.Get("If-Match"); im != "" && !strings.Contains(im, metadata["ETag"].(string)) {
		http.Error(writer, http.StatusText(http.StatusPreconditionFailed), http.StatusPreconditionFailed)
		return
	}
	if inm := request.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, metadata["ETag"].(string)) {
		http.Error(writer, http.StatusText(http.StatusNotModified), http.StatusNotModified)
		return
	}
	if ius, err := ParseDate(request.Header.Get("If-Unmodified-Since")); err == nil && lastModified.After(ius) {
		http.Error(writer, http.StatusText(http.StatusPreconditionFailed), http.StatusPreconditionFailed)
		return
	}
	if ims, err := ParseDate(request.Header.Get("If-Modified-Since")); err == nil && lastModified.Before(ims) {
		http.Error(writer, http.StatusText(http.StatusNotModified), http.StatusNotModified)
		return
	}
	headers.Set("Content-Type", metadata["Content-Type"].(string))
	headers.Set("Content-Length", metadata["Content-Length"].(string))

	if rangeHeader := request.Header.Get("Range"); rangeHeader != "" {
		fileSize, _ := file.Seek(0, os.SEEK_END)
		ranges, err := ParseRange(rangeHeader, fileSize)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusRequestedRangeNotSatisfiable), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if ranges != nil && len(ranges) == 1 {
			_, _ = file.Seek(ranges[0].start, os.SEEK_SET)
			writer.Header().Set("Content-Length", strconv.FormatInt(int64(ranges[0].end-ranges[0].start), 10))
			writer.WriteHeader(http.StatusPartialContent)
			io.CopyN(writer, file, ranges[0].end-ranges[0].start)
			return
		}
	}
	file.Seek(0, os.SEEK_SET)
	writer.WriteHeader(http.StatusOK)
	if request.Method == "GET" {
		io.Copy(writer, file)
	} else {
		writer.Write([]byte{})
	}
}

func (server ObjectServer) ObjPutHandler(writer *SwiftWriter, request *SwiftRequest, vars map[string]string) {
	outHeaders := writer.Header()
	hashDir, err := ObjHashDir(vars, server)
	if err != nil {
		http.Error(writer, "Insufficent Storage", 507)
		return
	}
	if inm := request.Header.Get("If-None-Match"); inm == "*" {
		dataFile := PrimaryFile(hashDir)
		if dataFile != "" && !strings.HasSuffix(dataFile, ".ts") {
			http.Error(writer, http.StatusText(http.StatusPreconditionFailed), http.StatusPreconditionFailed)
			return
		}
	}

	if os.MkdirAll(hashDir, 0770) != nil || os.MkdirAll(ObjTempDir(vars, server), 0770) != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	fileName := fmt.Sprintf("%s/%s.data", hashDir, request.Header.Get("X-Timestamp"))
	tempFile, err := ioutil.TempFile(ObjTempDir(vars, server), "PUT")
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()
	defer os.RemoveAll(tempFile.Name())
	metadata := make(map[string]interface{})
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["Content-Type"] = request.Header.Get("Content-Type")
	for key := range request.Header {
		if allowed, ok := server.allowedHeaders[key]; (ok && allowed) || strings.HasPrefix(key, "X-Object-Meta-") {
			metadata[key] = request.Header.Get(key)
		}
	}
	hash := md5.New()
	totalSize, err := io.Copy(hash, io.TeeReader(request.Body, tempFile))
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return
	}
	metadata["Content-Length"] = strconv.FormatInt(totalSize, 10)
	metadata["ETag"] = fmt.Sprintf("%x", hash.Sum(nil))
	requestEtag := request.Header.Get("ETag")
	if requestEtag != "" && requestEtag != metadata["ETag"].(string) {
		http.Error(writer, "Unprocessable Entity", 422)
		return
	}
	outHeaders.Set("ETag", metadata["ETag"].(string))
	WriteMetadata(int(tempFile.Fd()), metadata)

	if !server.disableFsync {
		tempFile.Sync()
	}
	os.Rename(tempFile.Name(), fileName)

	finalize := func() {
		UpdateContainer(metadata, request, vars)
		if request.Header.Get("X-Delete-At") != "" || request.Header.Get("X-Delete-After") != "" {
			UpdateDeleteAt(request, vars, metadata)
		}
		CleanupHashDir(hashDir)
		InvalidateHash(hashDir, !server.disableFsync)
	}
	if server.asyncCleanup {
		go finalize()
	} else {
		finalize()
	}
	http.Error(writer, http.StatusText(http.StatusCreated), http.StatusCreated)
}

func (server ObjectServer) ObjDeleteHandler(writer *SwiftWriter, request *SwiftRequest, vars map[string]string) {
	hashDir, err := ObjHashDir(vars, server)
	if err != nil {
		http.Error(writer, "Insufficent Storage", 507)
		return
	}
	dataFile := PrimaryFile(hashDir)
	if ida := request.Header.Get("X-If-Delete-At"); ida != "" {
		_, err = strconv.ParseInt(ida, 10, 64)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if dataFile != "" && !strings.HasSuffix(dataFile, ".ts") {
			http.Error(writer, http.StatusText(http.StatusPreconditionFailed), http.StatusPreconditionFailed)
			return
		}
		metadata, err := ReadMetadataFilename(fmt.Sprintf("%s/%s", hashDir, dataFile))
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		if _, ok := metadata["X-Delete-At"]; ok {
			if ida != metadata["X-Delete-At"] {
				http.Error(writer, http.StatusText(http.StatusPreconditionFailed), http.StatusPreconditionFailed)
				return
			}
		}
	}

	if os.MkdirAll(hashDir, 0770) != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	fileName := fmt.Sprintf("%s/%s.ts", hashDir, request.Header.Get("X-Timestamp"))
	tempFile, err := ioutil.TempFile(ObjTempDir(vars, server), "PUT")
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()
	metadata := make(map[string]interface{})
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	WriteMetadata(int(tempFile.Fd()), metadata)

	if !server.disableFsync {
		tempFile.Sync()
	}
	os.Rename(tempFile.Name(), fileName)
	finalize := func() {
		UpdateContainer(metadata, request, vars)
		if _, ok := metadata["X-Delete-At"]; ok {
			UpdateDeleteAt(request, vars, metadata)
		}
		CleanupHashDir(hashDir)
		InvalidateHash(hashDir, !server.disableFsync)
	}
	if server.asyncCleanup {
		go finalize()
	} else {
		finalize()
	}
	if !strings.HasSuffix(dataFile, ".data") {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	} else {
		http.Error(writer, "", http.StatusNoContent)
	}
}

func (server ObjectServer) ObjReplicateHandler(writer *SwiftWriter, request *SwiftRequest, vars map[string]string) {
	hashes, err := GetHashes(server, vars["device"], vars["partition"], strings.Split(vars["suffixes"], "-"))
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(PickleDumps(hashes)))
}

func GetDefault(h http.Header, key string, dfl string) string {
	val := h.Get(key)
	if val == "" {
		return dfl
	}
	return val
}

func (server ObjectServer) LogRequest(writer *SwiftWriter, request *SwiftRequest) {
	go server.logger.Info(fmt.Sprintf("%s - - [%s] \"%s %s\" %d %s \"%s\" \"%s\" \"%s\" %.4f \"%s\"",
		request.RemoteAddr,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		request.Method,
		request.URL.Path,
		writer.Status,
		GetDefault(writer.Header(), "Content-Length", "-"),
		GetDefault(request.Header, "Referer", "-"),
		GetDefault(request.Header, "X-Trans-Id", "-"),
		GetDefault(request.Header, "User-Agent", "-"),
		time.Since(request.Start).Seconds(),
		"-")) // TODO: "additional info"
}

func (server ObjectServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthcheck" {
		writer.Header().Set("Content-Length", "2")
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("OK"))
		return
	}
	parts := strings.SplitN(request.URL.Path, "/", 6)
	vars := make(map[string]string)
	if len(parts) > 1 {
		vars["device"] = parts[1]
		if len(parts) > 2 {
			vars["partition"] = parts[2]
			if len(parts) > 3 {
				vars["account"] = parts[3]
				vars["suffixes"] = parts[3]
				if len(parts) > 4 {
					vars["container"] = parts[4]
					if len(parts) > 5 {
						vars["obj"] = parts[5]
					}
				}
			}
		}
	}

	newWriter := &SwiftWriter{writer, 200}
	newRequest := &SwiftRequest{request, time.Now()}
	defer server.LogRequest(newWriter, newRequest) // log the request after return

	switch request.Method {
	case "GET":
		server.ObjGetHandler(newWriter, newRequest, vars)
	case "HEAD":
		server.ObjGetHandler(newWriter, newRequest, vars)
	case "PUT":
		server.ObjPutHandler(newWriter, newRequest, vars)
	case "DELETE":
		server.ObjDeleteHandler(newWriter, newRequest, vars)
	case "REPLICATE":
		server.ObjReplicateHandler(newWriter, newRequest, vars)
	}
}

func RunServer(conf string) {
	server := ObjectServer{driveRoot: "/srv/node", hashPathPrefix: "", hashPathSuffix: "",
		checkMounts: true, disableFsync: false, asyncCleanup: false,
		allowedHeaders: map[string]bool{"Content-Disposition": true,
			"Content-Encoding":      true,
			"X-Delete-At":           true,
			"X-Object-Manifest":     true,
			"X-Static-Large-Object": true,
		},
	}

	if swiftconf, err := LoadIniFile("/etc/swift/swift.conf"); err == nil {
		server.hashPathPrefix = swiftconf.GetDefault("swift-hash", "swift_hash_path_prefix", "")
		server.hashPathSuffix = swiftconf.GetDefault("swift-hash", "swift_hash_path_suffix", "")
	}

	serverconf, err := LoadIniFile(conf)
	if err != nil {
		panic(fmt.Sprintf("Unable to load %s", conf))
	}
	server.driveRoot = serverconf.GetDefault("DEFAULT", "devices", "/srv/node")
	server.checkMounts = LooksTrue(serverconf.GetDefault("DEFAULT", "mount_check", "true"))
	server.disableFsync = LooksTrue(serverconf.GetDefault("DEFAULT", "disable_fsync", "false"))
	server.asyncCleanup = LooksTrue(serverconf.GetDefault("DEFAULT", "async_cleanup", "false"))
	bindIP := serverconf.GetDefault("DEFAULT", "bind_ip", "0.0.0.0")
	bindPort, err := strconv.ParseInt(serverconf.GetDefault("DEFAULT", "bind_port", "8080"), 10, 64)
	if err != nil {
		panic("Invalid bind port format")
	}
	if allowedHeaders, ok := serverconf.Get("DEFAULT", "allowed_headers"); ok {
		headers := strings.Split(allowedHeaders, ",")
		for i := range headers {
			server.allowedHeaders[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(headers[i]))] = true
		}
	}

	sock, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindIP, bindPort))
	if err != nil {
		panic(fmt.Sprintf("Unable to bind %s:%d", bindIP, bindPort))
	}
	server.logger = SetupLogger(serverconf.GetDefault("DEFAULT", "log_facility", "LOG_LOCAL0"), "object-server")
	DropPrivileges(serverconf.GetDefault("DEFAULT", "user", "swift"))
	srv := &http.Server{Handler: server}
	srv.Serve(sock)
}

func main() {
	if os.Args[1] == "saio" {
		go RunServer("/etc/swift/object-server/1.conf")
		go RunServer("/etc/swift/object-server/2.conf")
		go RunServer("/etc/swift/object-server/3.conf")
		go RunServer("/etc/swift/object-server/4.conf")
		for {
			time.Sleep(10000)
		}
	}
	RunServer(os.Args[1])
}
