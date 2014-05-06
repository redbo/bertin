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
	"syscall"
	"time"
)

type ObjectServer struct {
	driveRoot      string
	hashPathPrefix string
	hashPathSuffix string
	checkMounts    bool
	disableFsync   bool
	allowedHeaders map[string]bool
	logger         *syslog.Writer
}

func ErrorResponse(writer http.ResponseWriter, status int) {
  	http.Error(writer, http.StatusText(status), status)
}

func (server ObjectServer) ObjGetHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string) {
	headers := writer.Header()
	hashDir, err := ObjHashDir(vars, server)
	if err != nil {
		ErrorResponse(writer, 507)
		return
	}
	// TODO: do proper logic, .meta files...
	dataFile := PrimaryFile(hashDir)
	if dataFile == "" || strings.HasSuffix(dataFile, ".ts") {
		ErrorResponse(writer, http.StatusNotFound)
		return
	}
	file, err := os.Open(fmt.Sprintf("%s/%s", hashDir, dataFile))
	if err != nil {
		ErrorResponse(writer, http.StatusNotFound)
		return
	}
	defer file.Close()
	metadata := ReadMetadata(int(file.Fd()))

	if deleteAt, ok := metadata["X-Delete-At"].(string); ok {
		if deleteTime, err := ParseDate(deleteAt); err == nil && deleteTime.Before(time.Now()) {
			ErrorResponse(writer, http.StatusNotFound)
			return
		}
	}

	lastModified, err := ParseDate(metadata["X-Timestamp"].(string))
	if err != nil {
		ErrorResponse(writer, http.StatusInternalServerError)
		return
	}

	if im := request.Header.Get("If-Match"); im != "" && !strings.Contains(im, metadata["ETag"].(string)) {
		writer.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if inm := request.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, metadata["ETag"].(string)) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	if ius, err := ParseDate(request.Header.Get("If-Unmodified-Since")); err == nil && ius.Before(lastModified) {
		writer.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if ims, err := ParseDate(request.Header.Get("If-Modified-Since")); err == nil && !lastModified.After(ims) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}

	headers.Set("Content-Length", metadata["Content-Length"].(string))
	headers.Set("ETag", fmt.Sprintf("\"%s\"", metadata["ETag"].(string)))
	headers.Set("X-Timestamp", metadata["X-Timestamp"].(string))
	headers.Set("Content-Type", metadata["Content-Type"].(string))
	headers.Set("Last-Modified", lastModified.Format(time.RFC1123))
	for key, value := range metadata {
		if strings.HasPrefix(key.(string), "X-Object-") {
			headers.Set(key.(string), value.(string))
		}
	}

	if rangeHeader := request.Header.Get("Range"); rangeHeader != "" {
		fileSize, _ := file.Seek(0, os.SEEK_END)
		ranges, err := ParseRange(rangeHeader, fileSize)
		if err != nil {
			ErrorResponse(writer, http.StatusRequestedRangeNotSatisfiable)
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

func (server ObjectServer) ObjPutHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string) {
	outHeaders := writer.Header()
	hashDir, err := ObjHashDir(vars, server)
	if err != nil {
		ErrorResponse(writer, 507)
		return
	}

	if os.MkdirAll(hashDir, 0770) != nil || os.MkdirAll(ObjTempDir(vars, server), 0770) != nil {
		ErrorResponse(writer, 500)
		return
	}
	fileName := fmt.Sprintf("%s/%s.data", hashDir, request.Header.Get("X-Timestamp"))
	tempFile, err := ioutil.TempFile(ObjTempDir(vars, server), "PUT")
	if err != nil {
		ErrorResponse(writer, 500)
		return
	}
	defer tempFile.Close()
	metadata := make(map[string]interface{})
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["Content-Type"] = request.Header.Get("Content-Type")
	for key := range request.Header {
		if strings.HasPrefix(key, "X-Object-Meta-") {
			metadata[key] = request.Header.Get(key)
		} else if allowed, ok := server.allowedHeaders[key]; ok && allowed {
			metadata[key] = request.Header.Get(key)
		}
	}
	var chunk [65536]byte
	totalSize := uint64(0)
	hash := md5.New()
	for {
		readLen, err := request.Body.Read(chunk[0:len(chunk)])
		if err != nil || readLen <= 0 {
			break
		}
		totalSize += uint64(readLen)
		hash.Write(chunk[0:readLen])
		tempFile.Write(chunk[0:readLen])
	}
	metadata["Content-Length"] = strconv.FormatUint(totalSize, 10)
	metadata["ETag"] = fmt.Sprintf("%x", hash.Sum(nil))
	requestEtag := request.Header.Get("ETag")
	if requestEtag != "" && requestEtag != metadata["ETag"].(string) {
		ErrorResponse(writer, 422)
		return
	}
	outHeaders.Set("ETag", metadata["ETag"].(string))
	WriteMetadata(int(tempFile.Fd()), metadata)

	if !server.disableFsync {
		syscall.Fsync(int(tempFile.Fd()))
	}
	syscall.Rename(tempFile.Name(), fileName)
	UpdateContainer(metadata, request, vars)
	if request.Header.Get("X-Delete-At") != "" || request.Header.Get("X-Delete-After") != "" {
		go UpdateDeleteAt(request, vars, metadata)
	}
	go CleanupHashDir(hashDir)
	go InvalidateHash(hashDir)
	ErrorResponse(writer, 201)
}

func (server ObjectServer) ObjDeleteHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string) {
	hashDir, err := ObjHashDir(vars, server)
	if err != nil {
		ErrorResponse(writer, 507)
		return
	}

	if os.MkdirAll(hashDir, 0770) != nil {
		ErrorResponse(writer, 500)
		return
	}
	fileName := fmt.Sprintf("%s/%s.ts", hashDir, request.Header.Get("X-Timestamp"))
	dataFile := PrimaryFile(hashDir)
	tempFile, err := ioutil.TempFile(ObjTempDir(vars, server), "PUT")
	if err != nil {
		ErrorResponse(writer, 500)
		return
	}
	defer tempFile.Close()
	metadata := make(map[string]interface{})
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	WriteMetadata(int(tempFile.Fd()), metadata)

	if !server.disableFsync {
		syscall.Fsync(int(tempFile.Fd()))
	}
	syscall.Rename(tempFile.Name(), fileName)
	UpdateContainer(metadata, request, vars)
	if _, ok := metadata["X-Delete-At"]; ok {
		go UpdateDeleteAt(request, vars, metadata)
	}
	go CleanupHashDir(hashDir)
	go InvalidateHash(hashDir)
	if !strings.HasSuffix(dataFile, ".data") {
		ErrorResponse(writer, 404)
	} else {
		ErrorResponse(writer, 204)
	}
}

func (server ObjectServer) ObjReplicateHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string) {
	hashes, err := GetHashes(server, vars["device"], vars["partition"], strings.Split(vars["suffixes"], "-"))
	if err != nil {
		ErrorResponse(writer, 500)
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

type SaveStatusWriter struct {
	http.ResponseWriter
	Status int
}

func (w *SaveStatusWriter) WriteHeader(status int) {
  w.ResponseWriter.WriteHeader(status)
  w.Status = status
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
	start := time.Now()
	newWriter := &SaveStatusWriter{writer, 200}
	switch request.Method {
	case "GET":
		server.ObjGetHandler(newWriter, request, vars)
	case "HEAD":
		server.ObjGetHandler(newWriter, request, vars)
	case "PUT":
		server.ObjPutHandler(newWriter, request, vars)
	case "DELETE":
		server.ObjDeleteHandler(newWriter, request, vars)
	case "REPLICATE":
		server.ObjReplicateHandler(newWriter, request, vars)
	}

	server.logger.Info(fmt.Sprintf("%s - - [%s] \"%s %s\" %d %s \"%s\" \"%s\" \"%s\" %.4f \"%s\"",
		request.RemoteAddr,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		request.Method,
		request.URL.Path,
		newWriter.Status,
		GetDefault(writer.Header(), "Content-Length", "-"),
		GetDefault(request.Header, "Referer", "-"),
		GetDefault(request.Header, "X-Trans-Id", "-"),
		GetDefault(request.Header, "User-Agent", "-"),
		time.Since(start).Seconds(),
		"-")) // TODO: "additional info"
}

func RunServer(conf string) {
	server := ObjectServer{driveRoot: "/srv/node", hashPathPrefix: "", hashPathSuffix: "",
		checkMounts: true, disableFsync: false,
		allowedHeaders: map[string]bool{"Content-Disposition": true,
			"Content-Encoding":      true,
			"X-Delete-At":           true,
			"X-Object-Manifest":     true,
			"X-Static-Large-Object": true,
		},
	}

	if swiftconf, err := LoadIniFile("/etc/swift/swift.conf"); err == nil {
		server.hashPathPrefix = swiftconf.getDefault("swift-hash", "swift_hash_path_prefix", "")
		server.hashPathSuffix = swiftconf.getDefault("swift-hash", "swift_hash_path_suffix", "")
	}

	serverconf, err := LoadIniFile(conf)
	if err != nil {
		panic(fmt.Sprintf("Unable to load %s", conf))
	}
	server.driveRoot = serverconf.getDefault("DEFAULT", "devices", "/srv/node")
	server.checkMounts = LooksTrue(serverconf.getDefault("DEFAULT", "mount_check", "true"))
	server.disableFsync = LooksTrue(serverconf.getDefault("DEFAULT", "disable_fsync", "false"))
	bindIP := serverconf.getDefault("DEFAULT", "bind_ip", "0.0.0.0")
	bindPort, err := strconv.ParseInt(serverconf.getDefault("DEFAULT", "bind_port", "8080"), 10, 64)
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
	server.logger = SetupLogger(serverconf.getDefault("DEFAULT", "log_facility", "LOG_LOCAL0"), "object-server")
	DropPrivileges(serverconf.getDefault("DEFAULT", "user", "swift"))
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
