package main

import (
	"encoding/csv"
	"fmt"
	"github.com/google/differential-privacy/go/dpagg"
	"github.com/google/differential-privacy/go/noise"
	"io"
	"math"
	"os"
	"strconv"
	"time"
)

const (
	// openingHour is the hour when visitors start entering the restaurant.
	openingHour = 9
	// closingHour is the hour when visitors stop entering the restaurant.
	closingHour = 20
)

var (
	ln3 = math.Log(3)
)

// Visit stores data about single visit of a visitor to the restaurant.
type Visit struct {
	VisitorID    int64
	VisitTime    time.Time
	MinutesSpent int64
	EurosSpent   int64
	Day          int
}

// CountVisitsPerHourScenario loads the input file, calculates non-anonymized and
// anonymized counts of visitors entering a restaurant every hour, and prints results
// to nonPrivateResultsOutputFile and privateResultsOutputFile.
// Uses dpagg.Count for calculating anonymized counts.
type CountVisitsPerHourScenario struct{}

// Calculates the raw count of the given visits per hour of day.
// Returns the map that maps an hour to a raw count of visits for the hours between
// OpeningHour and ClosingHour.
func (sc *CountVisitsPerHourScenario) getNonPrivateResults(dayVisits []Visit) map[int64]int64 {
	counts := make(map[int64]int64)
	for _, visit := range dayVisits {
		h := visit.VisitTime.Hour()
		counts[int64(h)]++
	}
	return counts
}

// Calculates the anonymized (i.e., "private") counts of the given visits per hour of day.
// Returns the map that maps an hour to an anonymized count of visits for the hours between
// OpeningHour and ClosingHour.
func (sc *CountVisitsPerHourScenario) getPrivateResults(dayVisits []Visit) map[int64]int64 {
	hourToDpCount := make(map[int64]*dpagg.Count)

	for h := int64(openingHour); h <= closingHour; h++ {
		// Construct dpagg.Count objects which will be used to calculate DP counts.
		// One dpagg.Count is created for every work hour.
		hourToDpCount[h] = dpagg.NewCount(&dpagg.CountOptions{
			Epsilon:                  ln3,
			MaxPartitionsContributed: 1,
			Noise:                    noise.Laplace(),
		})
	}

	for _, visit := range dayVisits {
		h := visit.VisitTime.Hour()
		hourToDpCount[int64(h)].Increment()
	}

	privateCounts := make(map[int64]int64)
	for h, dpCount := range hourToDpCount {
		privateCounts[h] = dpCount.Result()
	}

	return privateCounts
}

func readVisitsFromCSV(inputFile string) ([]Visit, error) {
	csvFile, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't open the csv file = %q, err = %v", inputFile, err)
	}

	defer csvFile.Close()

	visits := make([]Visit, 0)
	r := csv.NewReader(csvFile)
	skipLine := false
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("couldn't read the csv file = %q, err = %v", inputFile, err)
		}

		if len(record) != 5 {
			return nil, fmt.Errorf("the csv file = %q has incorrect format", inputFile)
		}

		// Skip the first line in the csv file which contains the header.
		if !skipLine {
			skipLine = true
			continue
		}

		visitorID, err := toInt64(record[0])
		if err != nil {
			return nil, fmt.Errorf("couldn't read VisitorID = %s as int64 in the csv file = %q, err = %v", record[0], inputFile, err)
		}
		visitTime, err := toTime(record[1])
		if err != nil {
			return nil, fmt.Errorf("couldn't read VisitTime = %s as time (in 3:04PM format) in the csv file = %q, err = %v", record[1], inputFile, err)
		}
		minutesSpent, err := toInt64(record[2])
		if err != nil {
			return nil, fmt.Errorf("couldn't read MinutesSpent = %s as int64 in the csv file = %q, err = %v", record[2], inputFile, err)
		}
		eurosSpent, err := toInt64(record[3])
		if err != nil {
			return nil, fmt.Errorf("couldn't read EurosSpent = %s as int64 in the csv file = %q, err = %v", record[3], inputFile, err)
		}
		day, err := toInt(record[4])
		if err != nil {
			return nil, fmt.Errorf("couldn't read Day = %s as int in the csv file = %s, err = %v", record[4], inputFile, err)
		}

		visits = append(visits,
			Visit{
				VisitorID:    visitorID,
				VisitTime:    visitTime,
				MinutesSpent: minutesSpent,
				EurosSpent:   eurosSpent,
				Day:          day,
			})
	}

	return visits, nil
}

func writeResultsToCSV(results map[int64]int64, outputFile string) error {
	csvFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("couldn't open the csv file = %q, err = %v", outputFile, err)
	}

	writer := csv.NewWriter(csvFile)

	for key, value := range results {
		data := []string{toString(key), toString(value)}
		err := writer.Write(data)
		if err != nil {
			return fmt.Errorf(
				"couldn't write to the csv file = %q, err = %v",
				outputFile, combineErrors(err, csvFile.Close()))
		}
	}

	writer.Flush()
	err = writer.Error()

	if err != nil {
		return fmt.Errorf(
			"couldn't write to the csv file = %q, err = %v",
			outputFile, combineErrors(err, csvFile.Close()))
	}

	err = csvFile.Close()
	if err != nil {
		return fmt.Errorf("couldn't close the csv file = %q, err = %v", outputFile, err)
	}

	return nil
}

func toString(n int64) string {
	return strconv.FormatInt(n, 10)
}

func toInt64(str string) (int64, error) {
	return strconv.ParseInt(str, 10, 64)
}

func toInt(str string) (int, error) {
	res, err := strconv.ParseInt(str, 10, 32)
	if err == nil {
		return int(res), err
	}
	return 0, err
}

func toTime(str string) (time.Time, error) {
	return time.Parse(time.Kitchen, str)
}

func combineErrors(errors ...error) string {
	var nonNilErrors []error
	for _, err := range errors {
		if err != nil {
			nonNilErrors = append(nonNilErrors, err)
		}
	}
	return fmt.Sprintf("%+v", nonNilErrors)
}

// In this example, Alice wants to share information with potential clients in order to let them know when the restaurant is most busy.
//
// For this, we will count how many visitors enter the restaurant at every hour of a particular day.
// For simplicity, assume that a visitor comes to the restaurant at most once a day.
// Thus, each visitor may only be present at most once in the whole dataset, since the dataset represents a single day of restaurant visits.
//
// The day_data.csv file contains visit data for a single day.
// It includes the visitor’s ID, a timestamp of when the visitor entered the restaurant,
// the duration of the visitor's visit to the restaurant (in minutes), and the money the visitor spent at the restaurant.
//
// More example: https://github.com/google/differential-privacy/blob/main/examples/go/README.md
func main() {

	inputFile := "day_data.csv"
	nonPrivateResultsOutputFile := "non_private.csv"
	privateResultsOutputFile := "private.csv"

	sc := &CountVisitsPerHourScenario{}
	visits, err := readVisitsFromCSV(inputFile)
	if err != nil {
		fmt.Printf("readVisitsFromCSV err: %s", err)
		os.Exit(-1)
	}

	nonPrResults := sc.getNonPrivateResults(visits)
	prResults := sc.getPrivateResults(visits)
	err = writeResultsToCSV(nonPrResults, nonPrivateResultsOutputFile)
	if err != nil {
		fmt.Printf("writeResultsToCSV err: %s", err)
		os.Exit(-1)
	}
	err = writeResultsToCSV(prResults, privateResultsOutputFile)
	if err != nil {
		fmt.Printf("writeResultsToCSV err: %s", err)
		os.Exit(-1)
	}
	return
}
