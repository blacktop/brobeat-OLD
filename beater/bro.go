package beater

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// BroHeaderFields log file header
type BroHeaderFields struct {
	Separator    string   `json:"separator,omitempty"`
	SetSeparator string   `json:"set_separator,omitempty"`
	EmptyField   string   `json:"empty_field,omitempty"`
	UnsetField   string   `json:"unset_field,omitempty"`
	Path         string   `json:"path,omitempty"`
	Open         string   `json:"open,omitempty"`
	Fields       []string `json:"fields"`
	Types        []string `json:"types"`
}

// BroField log line field
type BroField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// BroLogLine log entry
type BroLogLine struct {
	Type         string     `json:"type,omitempty"`
	Created      string     `json:"created,omitempty"`
	SetSeparator string     `json:"set_separator,omitempty"`
	EmptyField   string     `json:"empty_field,omitempty"`
	UnsetField   string     `json:"unset_field,omitempty"`
	Fields       []BroField `json:"fields,omitempty"`
}

// ReadHeader parses the bro log header
func ReadHeader(filePath string) BroHeaderFields {

	// #separator \x09
	// #set_separator	,
	// #empty_field	(empty)
	// #unset_field	-
	// #path	http
	// #open	2016-12-28-16-25-43
	// #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types	uri_vars	cookie_vars
	// #types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]

	hFields := BroHeaderFields{}

	f, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	hFields.Separator = strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#separator"))

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	hFields.SetSeparator = strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#set_separator"))

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	hFields.EmptyField = strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#empty_field"))

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	hFields.UnsetField = strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#unset_field"))

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	hFields.Path = strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#path"))

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	layout := "2006-01-02-15-04-05"
	t, _ := time.Parse(layout, strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#open")))
	hFields.Open = t.Format(time.RFC3339Nano)

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	fields := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#fields"))
	rFields := csv.NewReader(strings.NewReader(fields))
	rFields.Comma = '\t'
	hFields.Fields, err = rFields.Read()
	if err != nil {
		fmt.Println(err)
	}

	_ = scanner.Scan()
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading header:", err)
	}
	types := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#types"))
	rTypes := csv.NewReader(strings.NewReader(types))
	rTypes.Comma = '\t'
	hFields.Types, err = rTypes.Read()
	if err != nil {
		fmt.Println(err)
	}

	return hFields
}

// ParseLogFile parses out a bro log file
func ParseLogFile() {
	broHeader := ReadHeader("./data/http.log")

	csvFile, err := os.Open("./data/http.log")
	if err != nil {
		fmt.Println(err)
	}
	defer csvFile.Close()

	r := csv.NewReader(csvFile)
	r.Comma = '\t'
	r.Comment = '#'
	r.LazyQuotes = true

	lines, err := r.ReadAll()
	if err != nil {
		log.Fatalf("error reading all lines: %v", err)
	}
	for _, line := range lines {
		broLine := BroLogLine{
			Type:         broHeader.Path,
			Created:      broHeader.Open,
			SetSeparator: broHeader.SetSeparator,
			UnsetField:   broHeader.UnsetField,
			EmptyField:   broHeader.EmptyField,
			Fields:       make([]BroField, len(broHeader.Fields)),
		}
		for j, word := range line {
			broField := BroField{
				Name:  broHeader.Fields[j],
				Type:  broHeader.Types[j],
				Value: word,
			}
			broLine.Fields[j] = broField
		}
		broJSON, err := json.Marshal(broLine)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(broJSON))
	}
}
