package report_test

import "github.com/Lutfifakee-Project/owntrace/internal/report"

func mustJSON(d *report.Data) []byte {
	b, err := d.JSON()
	if err != nil {
		panic(err)
	}
	return b
}

func mustCSV(d *report.Data) []byte {
	b, err := d.CSV()
	if err != nil {
		panic(err)
	}
	return b
}
