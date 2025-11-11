// Package store fetches the weather data from WeatherAPI
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WeatherStore implements the WeatherReporter interface to define fetch logic
type WeatherStore struct {
	BaseAPIUrl string
	APIKey     string
}

// NewWeatherStore is constructor for store
func NewWeatherStore(baseAPIUrl string, APIKey string) WeatherReporter {
	return &WeatherStore{
		BaseAPIUrl: baseAPIUrl,
		APIKey:     APIKey,
	}
}

// GetCurrentWeatherReport fetches the current weather report
func (w WeatherStore) GetCurrentWeatherReport(ctx context.Context, location string) (map[string]interface{}, error) {

	responseData := make(map[string]interface{})

	APIUrl := fmt.Sprintf("%s/current.json?key=%s&q=%s&aqi=yes", w.BaseAPIUrl, w.APIKey, location)

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIUrl, nil)
	if err != nil {
		return responseData, fmt.Errorf("error creating request to fetch current weather data, %w", err)
	}

	// set headers
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    15,
			IdleConnTimeout: 10 * time.Second,
		},
	}

	// send request and get response
	resp, err := client.Do(req)
	if err != nil {
		return responseData, fmt.Errorf("error sending response to fetch current weather data, %w", err)
	}
	defer resp.Body.Close()

	// parse response data
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return responseData, fmt.Errorf("error parsing response of current weather data, %w", err)
	}

	return responseData, nil
}

// GetHistoricalWeatherReport fetches the historical weather report upto last 7th day from today
func (w WeatherStore) GetHistoricalWeatherReport(ctx context.Context, location string, date string) (map[string]interface{}, error) {

	responseData := make(map[string]interface{})

	APIUrl := fmt.Sprintf("%s/history.json?key=%s&q=%s&dt=%s", w.BaseAPIUrl, w.APIKey, location, date)

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIUrl, nil)
	if err != nil {
		return responseData, fmt.Errorf("error creating request to fetch historical data, %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    15,
			IdleConnTimeout: 8 * time.Second,
		},
	}

	// send request and get response
	resp, err := client.Do(req)
	if err != nil {
		return responseData, fmt.Errorf("error sending request to fetch historical data, %w", err)
	}
	defer resp.Body.Close()

	// parse response data
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return responseData, fmt.Errorf("error parsing response of historical data, %w", err)
	}

	return responseData, nil
}

// GetAstronomicalReport fetches the astronomy report of today
func (w WeatherStore) GetAstronomicalReport(ctx context.Context, location string) (map[string]interface{}, error) {

	responseData := make(map[string]interface{})

	APIUrl := fmt.Sprintf("%s/astronomy.json?key=%s&q=%s", w.BaseAPIUrl, w.APIKey, location)

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIUrl, nil)
	if err != nil {
		return responseData, fmt.Errorf("error creating request to fetch astronomy data, %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    15,
			IdleConnTimeout: 8 * time.Second,
		},
	}

	// send request and get response
	resp, err := client.Do(req)
	if err != nil {
		return responseData, fmt.Errorf("error sending request to fetch astronomy data, %w", err)
	}
	defer resp.Body.Close()

	// parse response data
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return responseData, fmt.Errorf("error parsing response of astronomy data, %w", err)
	}

	return responseData, nil
}

// GetForecastWeatherReport fetches the forecast data upto 3 days from today
func (w WeatherStore) GetForecastWeatherReport(ctx context.Context, location string, noOfDays string) (map[string]interface{}, error) {

	responseData := make(map[string]interface{})

	APIUrl := fmt.Sprintf("%s/forecast.json?key=%s&q=%s&days=%s&aqi=yes&alerts=yes", w.BaseAPIUrl, w.APIKey, location, noOfDays)

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIUrl, nil)
	if err != nil {
		return responseData, fmt.Errorf("error creating request to fetch forecast data, %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    15,
			IdleConnTimeout: 8 * time.Second,
		},
	}

	// send request and get response
	resp, err := client.Do(req)
	if err != nil {
		return responseData, fmt.Errorf("error sending request to fetch forecast data, %w", err)
	}
	defer resp.Body.Close()

	// parse response data
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return responseData, fmt.Errorf("error parsing response of forecast data, %w", err)
	}

	return responseData, nil
}
