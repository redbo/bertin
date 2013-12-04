package main

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vaughan0/go-ini"
)

type httpRange struct {
	start, end int64
}

func ReadMetadata(fd int) map[interface{}]interface{} {
	var pickledMetadata [32768]byte
	offset := 0
	for index := 0; ; index += 1 {
		var metadataName string
		if index == 0 {
			metadataName = "user.swift.metadata"
		} else {
			metadataName = fmt.Sprintf("user.swift.metadata%d", index)
		}
		length := FGetXattr(fd, metadataName, pickledMetadata[offset:])
		if length <= 0 {
			break
		}
		offset += length
	}
	v := PickleLoads(string(pickledMetadata[0:offset]))
	return v.(map[interface{}]interface{})
}

func WriteMetadata(fd int, v map[string]interface{}) {
	buf := PickleDumps(v)
	for index := 0; len(buf) > 0; index++ {
		var metadataName string
		if index == 0 {
			metadataName = "user.swift.metadata"
		} else {
			metadataName = fmt.Sprintf("user.swift.metadata%d", index)
		}
		writelen := 254
		if len(buf) < writelen {
			writelen = len(buf)
		}
		FSetXattr(fd, metadataName, []byte(buf[0:writelen]))
		buf = buf[writelen:len(buf)]
	}
}

func InvalidateHash(hashDir string) {
	suffDir := filepath.Dir(hashDir)
	partitionDir := filepath.Dir(suffDir)
	pklFile := fmt.Sprintf("%s/hashes.pkl", partitionDir)
	data, err := ioutil.ReadFile(pklFile)
	if err != nil {
		return
	}
	v := PickleLoads(string(data))
	v.(map[string]interface{})[suffDir] = nil
	// TODO: tmp file, fsync, rename
	ioutil.WriteFile(pklFile, []byte(PickleDumps(v)), 0666)
}

func ObjHashDir(vars map[string]string, config ServerConfig) (string, error) {
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%s/%s/%s/%s%s", config.hashPathPrefix, vars["account"],
		vars["container"], vars["obj"], config.hashPathSuffix))
	hexHash := fmt.Sprintf("%x", h.Sum(nil))
	suffix := hexHash[29:32]
	devicePath := fmt.Sprintf("%s/%s", config.driveRoot, vars["device"])
	if config.checkMounts {
		mounted, err := IsMount(devicePath)
		if err != nil || mounted != true {
			return "", errors.New("Not mounted")
		}
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s", devicePath, "objects", vars["partition"], suffix, hexHash), nil
}

func ObjTempDir(vars map[string]string, config ServerConfig) string {
	return fmt.Sprintf("%s/%s/%s", config.driveRoot, vars["device"], "tmp")
}

func PrimaryFile(directory string) string {
	fileList, err := ioutil.ReadDir(directory)
	if err != nil {
		return ""
	}
	for index := len(fileList) - 1; index >= 0; index-- {
		filename := fileList[index].Name()
		if strings.HasSuffix(filename, ".ts") || strings.HasSuffix(filename, ".data") {
			return filename
		}
	}
	return ""
}

func CleanupHashDir(directory string) {
	fileList, err := ioutil.ReadDir(directory)
	if err != nil {
		return
	}
	deleteRest := false
	for index := len(fileList) - 1; index >= 0; index-- {
		filename := fileList[index].Name()
		if deleteRest {
			os.RemoveAll(fmt.Sprintf("%s/%s", directory, filename))
		} else if strings.HasSuffix(filename, ".ts") || strings.HasSuffix(filename, ".data") {
			deleteRest = true
		}
	}
}

func Urlencode(str string) string {
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
		if err != nil || (resp.StatusCode/100) != 2 {
			continue
			// TODO: async update files
		}
	}
}

func ParseRange(rangeHeader string, fileSize int64) ([]httpRange, error) {
	rangeHeader = strings.Replace(strings.ToLower(rangeHeader), " ", "", -1)
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, nil
	}
	rangeHeader = rangeHeader[6:]
	var reqRanges []httpRange
	rangeStrings := strings.Split(rangeHeader, ",")
	for _, rng := range rangeStrings {
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
			} else if end > fileSize {
				reqRanges = append(reqRanges, httpRange{0, fileSize})
			} else {
				reqRanges = append(reqRanges, httpRange{fileSize - end, fileSize})
			}
		} else if beginend[1] == "" {
			begin, err := strconv.ParseInt(beginend[0], 10, 64)
			if err != nil {
				return nil, errors.New("invalid begin with no end")
			}
			if begin < fileSize {
				reqRanges = append(reqRanges, httpRange{begin, fileSize})
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
			if begin > fileSize {
				return nil, errors.New("Begin bigger than file")
			}
			if end+1 < fileSize {
				reqRanges = append(reqRanges, httpRange{begin, end + 1})
			} else {
				reqRanges = append(reqRanges, httpRange{begin, fileSize})
			}
		}
	}
	return reqRanges, nil
}

func ParseDate(date string) (time.Time, error) {
	if ius, err := time.Parse(time.RFC1123, date); err == nil {
		return ius, nil
	}
	if ius, err := time.Parse(time.RFC1123Z, date); err == nil {
		return ius, nil
	}
	if ius, err := time.Parse(time.ANSIC, date); err == nil {
		return ius, nil
	}
	if timestamp, err := strconv.ParseFloat(date, 64); err == nil {
		nans := int64(math.Mod(timestamp*1.0e9, 1e9))
		return time.Unix(int64(timestamp), nans), nil
	}
	return time.Now(), errors.New("invalid time")
}

func IsMount(dir string) (bool, error) {
	dir = filepath.Clean(dir)
	if fileinfo, err := os.Stat(dir); err == nil {
		if parentinfo, err := os.Stat(filepath.Dir(dir)); err == nil {
			return fileinfo.Sys().(*syscall.Stat_t).Dev != parentinfo.Sys().(*syscall.Stat_t).Dev, nil
		} else {
			return false, errors.New("Unable to stat parent")
		}
	} else {
		return false, errors.New("Unable to stat directory")
	}
}

func LooksTrue(check string) bool {
	check = strings.TrimSpace(strings.ToLower(check))
	return check == "true" || check == "yes" || check == "1" || check == "on" || check == "t" || check == "y"
}

type IniFile struct{ ini.File }

func (f IniFile) getDefault(section string, key string, dfl string) string {
	if value, ok := f.Get(section, key); ok {
		return value
	}
	return dfl
}

func LoadIniFile(filename string) (IniFile, error) {
	file := IniFile{make(ini.File)}
	return file, file.LoadFile(filename)
}
