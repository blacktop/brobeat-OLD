package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

// "github.com/elastic/beats/libbeat/beat"
// "github.com/blacktop/brobeat/beater"

func readHeader(filePath string) map[string]string {

	// #separator \x09
	// #set_separator	,
	// #empty_field	(empty)
	// #unset_field	-
	// #path	http
	// #open	2016-12-28-16-25-43
	// #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types	uri_vars	cookie_vars
	// #types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]

	lFields := make(map[string]string)

	f, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	_ = scanner.Scan()
	separator := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#separator"))
	fmt.Println(separator)

	_ = scanner.Scan()
	set_separator := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#set_separator"))
	fmt.Println(set_separator)

	_ = scanner.Scan()
	empty_field := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#empty_field"))
	fmt.Println(empty_field)

	_ = scanner.Scan()
	unset_field := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#unset_field"))
	fmt.Println(unset_field)

	_ = scanner.Scan()
	path := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#path"))
	fmt.Println(path)

	_ = scanner.Scan()
	open := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#open"))
	fmt.Println(open)

	_ = scanner.Scan()
	fields := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#fields"))
	rFields := csv.NewReader(strings.NewReader(fields))
	rFields.Comma = '\t'
	fieldNames, err := rFields.Read()
	if err != nil {
		fmt.Println(err)
	}

	_ = scanner.Scan()
	types := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#types"))
	rTypes := csv.NewReader(strings.NewReader(types))
	rTypes.Comma = '\t'
	fieldTypes, err := rTypes.Read()
	if err != nil {
		fmt.Println(err)
	}

	if len(fieldNames) == len(fieldTypes) {
		for i, name := range fieldNames {
			lFields[name] = fieldTypes[i]
		}
	} else {
		fmt.Println("ERROR!!!")
	}

	return lFields
}

func main() {
	// err := beat.Run("brobeat", "", beater.New)
	// if err != nil {
	// 	os.Exit(1)
	// }
	fmt.Println(readHeader("./data/http.log"))
	os.Exit(0)

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
	for i, line := range lines {
		if i > 9 {
			break
		}
		fmt.Println(line)
	}
	// recs, err := r.Read()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(recs)
}
