// Package store fetches the weather data from WeatherAPI
package store

import (
	"context"
)

// WeatherReporter declares methods that could be implemented to define logic for fetching data or creating mock
type WeatherReporter interface {
	GetCurrentWeatherReport(ctx context.Context, location string) (map[string]interface{}, error)
	GetHistoricalWeatherReport(ctx context.Context, location string, date string) (map[string]interface{}, error)
	GetAstronomicalReport(ctx context.Context, location string) (map[string]interface{}, error)
	GetForecastWeatherReport(ctx context.Context, location string, noOfDays string) (map[string]interface{}, error)
}
