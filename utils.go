package main

import (
    "os"
    "io"
    "io/ioutil"
    "fmt"
    "crypto/md5"
    "strings"
    "net/http"
    "path/filepath"
    "strconv"
    "errors"
    "net/url"

    "github.com/redbo/bertin/pickle"
)

type httpRange struct {
    start, end int64
}

func ReadMetadata(fd int) (map[interface{}]interface{}) {
    var pickled_metadata [32768]byte
    offset := 0
    for index := 0; ; index += 1 {
        var metadata_name string
        if index == 0 {
            metadata_name = "user.swift.metadata"
        } else {
            metadata_name = fmt.Sprintf("user.swift.metadata%d", index)
        }
        length := FGetXattr(fd, metadata_name, pickled_metadata[offset:])
        if length <= 0 {
            break
        }
        offset += length
    }
    v := pickle.Loads(string(pickled_metadata[0:offset]))
    return v.(map[interface{}]interface{})
}

func WriteMetadata(fd int, v map[string]interface{}) {
    buf := pickle.Dumps(v)
    for index := 0; len(buf) > 0; index++ {
        var metadata_name string
        if index == 0 {
            metadata_name = "user.swift.metadata"
        } else {
            metadata_name = fmt.Sprintf("user.swift.metadata%d", index)
        }
        writelen := 254
        if len(buf) < writelen {
            writelen = len(buf)
        }
        FSetXattr(fd, metadata_name, []byte(buf[0:writelen]))
        buf = buf[writelen:len(buf)]
    }
}

func InvalidateHash(hash_dir string) {
    suff_dir := filepath.Dir(hash_dir)
    partition_dir := filepath.Dir(suff_dir)
    pkl_file := fmt.Sprintf("%s/hashes.pkl", partition_dir)
    data, err := ioutil.ReadFile(pkl_file)
    if err != nil {
        return
    }
    v := pickle.Loads(string(data))
    v.(map[string]interface{})[suff_dir] = nil
    // TODO: tmp file, fsync, rename
    ioutil.WriteFile(pkl_file, []byte(pickle.Dumps(v)), 0666)
}

func ObjHashDir(vars map[string]string, config ServerConfig) (string) {
    h := md5.New()
    io.WriteString(h, fmt.Sprintf("%s/%s/%s/%s%s", config.hash_path_prefix, vars["account"],
                   vars["container"], vars["obj"], config.hash_path_suffix))
    hex_hash := fmt.Sprintf("%x", h.Sum(nil))
    suffix := hex_hash[29:32]
    return fmt.Sprintf("%s/%s/%s/%s/%s/%s", config.drive_root, vars["device"], "objects", vars["partition"], suffix, hex_hash)
}

func ObjTempDir(vars map[string]string, config ServerConfig) (string) {
    return fmt.Sprintf("%s/%s/%s", config.drive_root, vars["device"], "tmp")
}

func PrimaryFile(directory string) (string) {
    file_list, err := ioutil.ReadDir(directory)
    if err != nil {
        return ""
    }
    for index := len(file_list) - 1; index >= 0; index-- {
        filename := file_list[index].Name()
        if strings.HasSuffix(filename, ".ts") || strings.HasSuffix(filename, ".data") {
            return filename
        }
    }
    return ""
}

func CleanupHashDir(directory string) {
    file_list, err := ioutil.ReadDir(directory)
    if err != nil {
        return
    }
    delete_rest := false
    for index := len(file_list) - 1; index >= 0; index-- {
        filename := file_list[index].Name()
        if delete_rest {
            os.RemoveAll(fmt.Sprintf("%s/%s", directory, filename))
        } else if strings.HasSuffix(filename, ".ts") || strings.HasSuffix(filename, ".data") {
            delete_rest = true
        }
    }
}

func Urlencode(str string) (string) {
    return strings.Replace(url.QueryEscape(str), "+", "%20", -1)
}

func UpdateContainer(operation string, metadata map[string]interface{}, request *http.Request, vars map[string]string) {
    client := &http.Client{}
    contpartition := request.Header.Get("X-Container-Partition")
    conthosts := strings.Split(request.Header.Get("X-Container-Host"), ",")
    contdevices := strings.Split(request.Header.Get("X-Container-Device"), ",")
    for index := range conthosts {
        if conthosts[index] == "" {
            break
        }
        host := conthosts[index]
        device := contdevices[index]
        url := fmt.Sprintf("http://%s/%s/%s/%s/%s/%s", host, device, contpartition,
            Urlencode(vars["account"]), Urlencode(vars["container"]), Urlencode(vars["obj"]))
        req, err := http.NewRequest(operation, url, nil)
        if err != nil {
            continue
        }
        req.Header.Add("X-Trans-Id", request.Header.Get("X-Trans-Id"))
        req.Header.Add("X-Timestamp", metadata["X-Timestamp"].(string))
        if operation != "DELETE" {
            req.Header.Add("X-Content-Type", metadata["Content-Type"].(string))
            req.Header.Add("X-Size", metadata["Content-Length"].(string))
            req.Header.Add("X-Etag", metadata["ETag"].(string))
        }
        resp, err := client.Do(req)
        if err != nil || (resp.StatusCode / 100) != 2 {
            continue
            // TODO: async update files
        }
    }
}

func parseRange(range_header string, file_size int64) ([]httpRange, error) {
    range_header = strings.Replace(strings.ToLower(range_header), " ", "", -1)
    if !strings.HasPrefix(range_header, "bytes=") {
        return nil, nil
    }
    range_header = range_header[6:]
    var req_ranges []httpRange
    range_strings := strings.Split(range_header, ",")
    for _, rng := range range_strings {
        beginend := strings.Split(rng, "-")
        if len(beginend) != 2 || (beginend[0] == "" && beginend[1] == "") {
            return nil, errors.New("invalid range format")
        }
        if beginend[0] == "" {
            end, err := strconv.ParseInt(beginend[1], 10, 64)
            if err != nil {
                return nil, errors.New("invalid end with no begin")
            }
            if end == 0 {
                return nil, errors.New("zero end with no begin")
            } else if end > file_size {
                req_ranges = append(req_ranges, httpRange{0, file_size})
            } else {
                req_ranges = append(req_ranges, httpRange{file_size - end, file_size})
            }
        } else if beginend[1] == "" {
            begin, err := strconv.ParseInt(beginend[0], 10, 64)
            if err != nil {
                return nil, errors.New("invalid begin with no end")
            }
            if begin < file_size {
                req_ranges = append(req_ranges, httpRange{begin, file_size})
            } else {
                continue
            }
        } else {
            begin, err := strconv.ParseInt(beginend[0], 10, 64)
            if err != nil {
                return nil, errors.New("invalid begin")
            }
            end, err := strconv.ParseInt(beginend[1], 10, 64)
            if err != nil {
                return nil, errors.New("invalid end")
            }
            if end < begin {
                return nil, errors.New("end before begin")
            }
            if begin > file_size {
                return nil, errors.New("Begin bigger than file")
            }
            if end + 1 < file_size {
                req_ranges = append(req_ranges, httpRange{begin, end + 1})
            } else {
                req_ranges = append(req_ranges, httpRange{begin, file_size})
            }
        }
    }
    return req_ranges, nil
}

