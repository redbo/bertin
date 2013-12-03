package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/context"
	"github.com/keep94/weblogs"
	"github.com/vaughan0/go-ini"
)

type ServerConfig struct {
	drive_root       string
	hash_path_prefix string
	hash_path_suffix string
	port             int64
}

func ErrorResponse(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Length", "0")
	writer.WriteHeader(status)
}

func ObjGetHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string, config ServerConfig) {
	headers := writer.Header()
	hash_dir := ObjHashDir(vars, config)
	// TODO: do proper logic, .meta files...
	data_file := PrimaryFile(hash_dir)
	if data_file == "" || strings.HasSuffix(data_file, ".ts") {
		ErrorResponse(writer, http.StatusNotFound)
		return
	}
	file, err := os.Open(fmt.Sprintf("%s/%s", hash_dir, data_file))
	if err != nil {
		ErrorResponse(writer, http.StatusNotFound)
		return
	}
	defer file.Close()
	metadata := ReadMetadata(int(file.Fd()))

	if delete_at, ok := metadata["X-Delete-At"]; ok {
		if delete_time, err := ParseDate(delete_at.(string)); err == nil && delete_time.Before(time.Now()) {
			ErrorResponse(writer, http.StatusNotFound)
			return
		}
	}

	last_modified, err := ParseDate(metadata["X-Timestamp"].(string))
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
	if ius, err := ParseDate(request.Header.Get("If-Unmodified-Since")); err == nil && ius.Before(last_modified) {
		writer.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if ims, err := ParseDate(request.Header.Get("If-Modified-Since")); err == nil && !last_modified.After(ims) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}

	headers.Set("Content-Length", metadata["Content-Length"].(string))
	headers.Set("ETag", fmt.Sprintf("\"%s\"", metadata["ETag"].(string)))
	headers.Set("X-Timestamp", metadata["X-Timestamp"].(string))
	headers.Set("Content-Type", metadata["Content-Type"].(string))
	headers.Set("Last-Modified", last_modified.Format(time.RFC1123))
	for key, value := range metadata {
		if strings.HasPrefix(key.(string), "X-Object-") {
			headers.Set(key.(string), value.(string))
		}
	}

	if range_header := request.Header.Get("Range"); range_header != "" {
		file_size, _ := file.Seek(0, os.SEEK_END)
		ranges, err := ParseRange(range_header, file_size)
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
	out_headers := writer.Header()
	hash_dir := ObjHashDir(vars, config)

	if os.MkdirAll(hash_dir, 0770) != nil || os.MkdirAll(ObjTempDir(vars, config), 0770) != nil {
		ErrorResponse(writer, 500)
		return
	}
	file_name := fmt.Sprintf("%s/%s.data", hash_dir, request.Header.Get("X-Timestamp"))
	temp_file, err := ioutil.TempFile(ObjTempDir(vars, config), "PUT")
	if err != nil {
		ErrorResponse(writer, 500)
		return
	}
	defer temp_file.Close()
	metadata := make(map[string]interface{})
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["Content-Type"] = request.Header.Get("Content-Type")
	var chunk [65536]byte
	total_size := uint64(0)
	hash := md5.New()
	for {
		read_len, err := request.Body.Read(chunk[0:len(chunk)])
		if err != nil || read_len <= 0 {
			break
		}
		total_size += uint64(read_len)
		hash.Write(chunk[0:read_len])
		temp_file.Write(chunk[0:read_len])
	}
	metadata["Content-Length"] = strconv.FormatUint(total_size, 10)
	metadata["ETag"] = fmt.Sprintf("%x", hash.Sum(nil))
	request_etag := request.Header.Get("ETag")
	if request_etag != "" && request_etag != metadata["ETag"].(string) {
		ErrorResponse(writer, 422)
		return
	}
	for key := range request.Header {
		if strings.HasPrefix(key, "X-Object-") {
			metadata[key] = request.Header.Get(key)
		}
	}
	out_headers.Set("ETag", metadata["ETag"].(string))
	WriteMetadata(int(temp_file.Fd()), metadata)

	syscall.Fsync(int(temp_file.Fd()))
	syscall.Rename(temp_file.Name(), file_name)
	UpdateContainer("PUT", metadata, request, vars)
	go CleanupHashDir(hash_dir)
	go InvalidateHash(hash_dir)
	ErrorResponse(writer, 201)
}

func ObjDeleteHandler(writer http.ResponseWriter, request *http.Request, vars map[string]string, config ServerConfig) {
	hash_dir := ObjHashDir(vars, config)

	if os.MkdirAll(hash_dir, 0770) != nil {
		ErrorResponse(writer, 500)
		return
	}
	file_name := fmt.Sprintf("%s/%s.ts", hash_dir, request.Header.Get("X-Timestamp"))
	data_file := PrimaryFile(hash_dir)
	temp_file, err := ioutil.TempFile(ObjTempDir(vars, config), "PUT")
	if err != nil {
		ErrorResponse(writer, 500)
		return
	}
	defer temp_file.Close()
	metadata := make(map[string]interface{})
	metadata["X-Timestamp"] = request.Header.Get("X-Timestamp")
	metadata["name"] = fmt.Sprintf("/%s/%s/%s", vars["account"], vars["container"], vars["obj"])
	WriteMetadata(int(temp_file.Fd()), metadata)

	syscall.Fsync(int(temp_file.Fd()))
	syscall.Rename(temp_file.Name(), file_name)
	UpdateContainer("DELETE", metadata, request, vars)
	go CleanupHashDir(hash_dir)
	go InvalidateHash(hash_dir)
	if !strings.HasSuffix(data_file, ".data") {
		ErrorResponse(writer, 404)
	} else {
		ErrorResponse(writer, 204)
	}
}

func (m ServerConfig) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthcheck" {
		writer.Header().Set("Content-Length", "2")
		writer.WriteHeader(200)
		writer.Write([]byte("OK"))
		return
	}
	parts := strings.SplitN(request.URL.Path, "/", 6)
	vars := map[string]string{"device": parts[1],
		"partition": parts[2],
		"account":   parts[3],
		"container": parts[4],
		"obj":       parts[5],
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
	}
}

func RunServer(conf string) {
	var ok bool
	config := ServerConfig{"", "", "", 0}

	swiftconf, err := ini.LoadFile("/etc/swift/swift.conf")
	if err != nil {
		return
	}
	config.hash_path_prefix, ok = swiftconf.Get("swift-hash", "swift_hash_path_prefix")
	if !ok {
		return
	}
	config.hash_path_suffix, ok = swiftconf.Get("swift-hash", "swift_hash_path_suffix")
	if !ok {
		return
	}

	serverconf, err := ini.LoadFile(conf)
	if err != nil {
		return
	}
	config.drive_root, ok = serverconf.Get("DEFAULT", "devices")
	if !ok {
		return
	}
	portstr, ok := serverconf.Get("DEFAULT", "bind_port")
	if !ok {
		return
	}
	config.port, err = strconv.ParseInt(portstr, 10, 64)
	if err != nil {
		return
	}

	handler := context.ClearHandler(weblogs.Handler(config))
	http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", config.port), handler)
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
