package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/context"
	"github.com/keep94/weblogs"
)

type ServerConfig struct {
	driveRoot      string
	hashPathPrefix string
	hashPathSuffix string
	checkMounts    bool
	disableFsync   bool
	allowedHeaders map[string]bool
}

func ErrorResponse(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Length", "0")
	writer.WriteHeader(status)
}

func ObjGetHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string, config ServerConfig) {
	headers := writer.Header()
	hashDir, err := ObjHashDir(vars, config)
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

func ObjPutHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string, config ServerConfig) {
	outHeaders := writer.Header()
	hashDir, err := ObjHashDir(vars, config)
	if err != nil {
		ErrorResponse(writer, 507)
		return
	}

	if os.MkdirAll(hashDir, 0770) != nil || os.MkdirAll(ObjTempDir(vars, config), 0770) != nil {
		ErrorResponse(writer, 500)
		return
	}
	fileName := fmt.Sprintf("%s/%s.data", hashDir, request.Header.Get("X-Timestamp"))
	tempFile, err := ioutil.TempFile(ObjTempDir(vars, config), "PUT")
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
		} else if allowed, ok := config.allowedHeaders[key]; ok && allowed {
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

	syscall.Fsync(int(tempFile.Fd()))
	syscall.Rename(tempFile.Name(), fileName)
	UpdateContainer(metadata, request, vars)
	if request.Header.Get("X-Delete-At") != "" || request.Header.Get("X-Delete-After") != "" {
		go UpdateDeleteAt(request, vars, metadata)
	}
	go CleanupHashDir(hashDir)
	go InvalidateHash(hashDir)
	ErrorResponse(writer, 201)
}

func ObjDeleteHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string, config ServerConfig) {
	hashDir, err := ObjHashDir(vars, config)
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
	tempFile, err := ioutil.TempFile(ObjTempDir(vars, config), "PUT")
	if err != nil {
		ErrorResponse(writer, 500)
		return
	}
	defer tempFile.Close()
	metadata := make(map[string]interface{})
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	WriteMetadata(int(tempFile.Fd()), metadata)

	if !config.disableFsync {
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

func ObjReplicateHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string, config ServerConfig) {
	hashes, err := GetHashes(config, vars["device"], vars["partition"], strings.Split(vars["suffixes"], "-"))
	if err != nil {
		ErrorResponse(writer, 500)
		return
	}
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(PickleDumps(hashes)))
}

func (m ServerConfig) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthcheck" {
		writer.Header().Set("Content-Length", "2")
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("OK"))
		return
	}
	parts := strings.SplitN(request.URL.Path, "/", 6)
	var vars map[string]string
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
	switch request.Method {
	case "GET":
		ObjGetHandler(writer, request, vars, m)
	case "HEAD":
		ObjGetHandler(writer, request, vars, m)
	case "PUT":
		ObjPutHandler(writer, request, vars, m)
	case "DELETE":
		ObjDeleteHandler(writer, request, vars, m)
	case "REPLICATE":
		ObjReplicateHandler(writer, request, vars, m)
	}
}

func RunServer(conf string) {
	config := ServerConfig{driveRoot: "/srv/node", hashPathPrefix: "", hashPathSuffix: "",
		checkMounts: true, disableFsync: false,
		allowedHeaders: map[string]bool{"Content-Disposition": true,
			"Content-Encoding":      true,
			"X-Delete-At":           true,
			"X-Object-Manifest":     true,
			"X-Static-Large-Object": true,
		},
	}

	if swiftconf, err := LoadIniFile("/etc/swift/swift.conf"); err == nil {
		config.hashPathPrefix = swiftconf.getDefault("swift-hash", "swift_hash_path_prefix", "")
		config.hashPathSuffix = swiftconf.getDefault("swift-hash", "swift_hash_path_suffix", "")
	}

	serverconf, err := LoadIniFile(conf)
	if err != nil {
		panic(fmt.Sprintf("Unable to load %s", conf))
	}
	config.driveRoot = serverconf.getDefault("DEFAULT", "devices", "/srv/node")
	config.checkMounts = LooksTrue(serverconf.getDefault("DEFAULT", "mount_check", "true"))
	config.disableFsync = LooksTrue(serverconf.getDefault("DEFAULT", "disable_fsync", "false"))
	bindIP := serverconf.getDefault("DEFAULT", "bind_ip", "0.0.0.0")
	bindPort, err := strconv.ParseInt(serverconf.getDefault("DEFAULT", "bind_port", "8080"), 10, 64)
	if err != nil {
		panic("Invalid bind port format")
	}
	if allowedHeaders, ok := serverconf.Get("DEFAULT", "allowed_headers"); ok {
		headers := strings.Split(allowedHeaders, ",")
		for i := range headers {
			config.allowedHeaders[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(headers[i]))] = true
		}
	}

	handler := context.ClearHandler(weblogs.Handler(config))
	sock, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindIP, bindPort))
	if err != nil {
		panic(fmt.Sprintf("Unable to bind %s:%d", bindIP, bindPort))
	}
	DropPrivileges(serverconf.getDefault("DEFAULT", "user", "swift"))
	server := &http.Server{Handler: handler}
	server.Serve(sock)
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
