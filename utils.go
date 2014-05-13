package main

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
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

const deleteAtDivisor = 3600
const deleteAtAccount = ".expiring_objects"

type httpRange struct {
	start, end int64
}

func ReadMetadataFd(fd int) (map[interface{}]interface{}, error) {
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
	return v.(map[interface{}]interface{}), nil
}

func ReadMetadataFilename(filename string) (map[interface{}]interface{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("Unable to open file.")
	}
	defer file.Close()
	return ReadMetadataFd(int(file.Fd()))
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
	// TODO: atomic
	ioutil.WriteFile(pklFile, []byte(PickleDumps(v)), 0666)
}

func HashCleanupListdir(hashDir string) ([]string, error) {
	fileList, err := ioutil.ReadDir(hashDir)
	if err != nil {
		return nil, nil
	}
	deleteRest := false
	returnList := []string{}
	for index := len(fileList) - 1; index >= 0; index-- {
		filename := fileList[index].Name()
		if deleteRest {
			os.RemoveAll(fmt.Sprintf("%s/%s", hashDir, filename))
		} else {
			returnList = append(returnList, filename)
			if strings.HasSuffix(filename, ".ts") || strings.HasSuffix(filename, ".data") {
				// TODO: check .ts time for expiration
				deleteRest = true
			}
		}
	}
	return returnList, nil
}

func CleanupHashDir(directory string) {
	_, _ = HashCleanupListdir(directory)
}

func RecalculateSuffixHash(suffixDir string) (string, error) {
	h := md5.New()
	hashList, err := ioutil.ReadDir(suffixDir)
	if err != nil {
		return "", err
	}
	for index := len(hashList) - 1; index >= 0; index-- {
		fileList, err := HashCleanupListdir(fmt.Sprintf("%s/%s", suffixDir, hashList[index]))
		// TODO: handle errors?
		if err != nil {
			return "", err
		}
		for _, fileName := range fileList {
			io.WriteString(h, fileName)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func GetHashes(server ObjectServer, device string, partition string, recalculate []string) (map[string]interface{}, error) {
	pklFile := fmt.Sprintf("%s/%s/%s/hashes.pkl", server.driveRoot, device, partition)
	data, err := ioutil.ReadFile(pklFile)
	if err != nil {
		return nil, err
	}
	v := PickleLoads(string(data)).(map[string]interface{})
	for _, suffix := range recalculate {
		v[suffix] = nil
	}
	// TODO: locking, check for updates and recurse, etc.
	for suffix, hash := range v {
		if hash == nil || hash == "" {
			v[suffix], err = RecalculateSuffixHash(fmt.Sprintf("%s/%s/%s/%s", server.driveRoot, device, partition, suffix))
			if err != nil {
				v[suffix] = nil
			}
		}
	}
	// TODO: atomic
	ioutil.WriteFile(pklFile, []byte(PickleDumps(v)), 0666)
	return v, nil
}

func ObjHashDir(vars map[string]string, server ObjectServer) (string, error) {
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%s/%s/%s/%s%s", server.hashPathPrefix, vars["account"],
		vars["container"], vars["obj"], server.hashPathSuffix))
	hexHash := fmt.Sprintf("%x", h.Sum(nil))
	suffix := hexHash[29:32]
	devicePath := fmt.Sprintf("%s/%s", server.driveRoot, vars["device"])
	if server.checkMounts {
		mounted, err := IsMount(devicePath)
		if err != nil || mounted != true {
			return "", errors.New("Not mounted")
		}
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s", devicePath, "objects", vars["partition"], suffix, hexHash), nil
}

func ObjTempDir(vars map[string]string, server ObjectServer) string {
	return fmt.Sprintf("%s/%s/%s", server.driveRoot, vars["device"], "tmp")
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

func Urlencode(str string) string {
	return strings.Replace(url.QueryEscape(str), "+", "%20", -1)
}

func UpdateContainer(metadata map[string]interface{}, request *http.Request, vars map[string]string) {
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
		req, err := http.NewRequest(request.Method, url, nil)
		if err != nil {
			continue
		}
		req.Header.Add("X-Trans-Id", request.Header.Get("X-Trans-Id"))
		req.Header.Add("X-Timestamp", metadata["X-Timestamp"].(string))
		if request.Method != "DELETE" {
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

// TODO: UNTESTED
func UpdateDeleteAt(request *http.Request, vars map[string]string, metadata map[string]interface{}) {
	if _, ok := metadata["X-Delete-At"]; !ok {
		return
	}
	deleteAt, err := ParseDate(metadata["X-Delete-At"].(string))
	if err != nil {
		return
	}
	client := &http.Client{}
	partition := request.Header.Get("X-Delete-At-Partition")
	host := request.Header.Get("X-Delete-At-Host")
	device := request.Header.Get("X-Delete-At-Device")

	deleteAtContainer := (deleteAt.Unix() / deleteAtDivisor) * deleteAtDivisor
	url := fmt.Sprintf("http://%s/%s/%s/%s/%d/%d-%s/%s/%s", host, device, partition, deleteAtAccount, deleteAtContainer,
		deleteAt.Unix(), Urlencode(vars["account"]), Urlencode(vars["container"]), Urlencode(vars["obj"]))
	req, err := http.NewRequest(request.Method, url, nil)
	req.Header.Add("X-Trans-Id", request.Header.Get("X-Trans-Id"))
	req.Header.Add("X-Timestamp", request.Header.Get("X-Timestamp"))
	req.Header.Add("X-Size", "0")
	req.Header.Add("X-Content-Type", "text/plain")
	req.Header.Add("X-Etag", metadata["ETag"])
	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode/100) != 2 {
		// TODO: async update files
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

var GMT *time.Location

func ParseDate(date string) (time.Time, error) {
	if GMT == nil {
		GMT, _ = time.LoadLocation("GMT")
	}
	if ius, err := time.ParseInLocation(time.RFC1123, date, GMT); err == nil {
		return ius, nil
	}
	if ius, err := time.ParseInLocation(time.RFC1123Z, date, GMT); err == nil {
		return ius, nil
	}
	if ius, err := time.ParseInLocation(time.ANSIC, date, GMT); err == nil {
		return ius, nil
	}
	if ius, err := time.ParseInLocation(time.RFC850, date, GMT); err == nil {
		return ius, nil
	}
	if timestamp, err := strconv.ParseFloat(date, 64); err == nil {
		nans := int64((timestamp - float64(int64(timestamp))) * 1.0e9)
		return time.Unix(int64(timestamp), nans).In(GMT), nil
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

func SetupLogger(facility string, prefix string) *syslog.Writer {
	facility_mapping := map[string]syslog.Priority{"LOG_USER": syslog.LOG_USER,
		"LOG_MAIL": syslog.LOG_MAIL, "LOG_DAEMON": syslog.LOG_DAEMON,
		"LOG_AUTH": syslog.LOG_AUTH, "LOG_SYSLOG": syslog.LOG_SYSLOG,
		"LOG_LPR": syslog.LOG_LPR, "LOG_NEWS": syslog.LOG_NEWS,
		"LOG_UUCP": syslog.LOG_UUCP, "LOG_CRON": syslog.LOG_CRON,
		"LOG_AUTHPRIV": syslog.LOG_AUTHPRIV, "LOG_FTP": syslog.LOG_FTP,
		"LOG_LOCAL0": syslog.LOG_LOCAL0, "LOG_LOCAL1": syslog.LOG_LOCAL1,
		"LOG_LOCAL2": syslog.LOG_LOCAL2, "LOG_LOCAL3": syslog.LOG_LOCAL3,
		"LOG_LOCAL4": syslog.LOG_LOCAL4, "LOG_LOCAL5": syslog.LOG_LOCAL5,
		"LOG_LOCAL6": syslog.LOG_LOCAL6, "LOG_LOCAL7": syslog.LOG_LOCAL7}
	logger, err := syslog.Dial("udp", "127.0.0.1:514", facility_mapping[facility], prefix)
	if err != nil || logger == nil {
		panic(fmt.Sprintf("Unable to dial logger: %s", err))
	}
	return logger
}
