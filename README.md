`Rest Weather Go` is a native Go implementation of the WeatherAPI, built to practice REST API fundamentals and other best practices for production-grade Go REST applications.

### Data Store
- Weather data is fetched via external API call to `https://api.weatherapi.com/v1`
- SQLite3 database is used to register users and their refresh tokens for authentication and authorization

### Logging
- Set built-in flags to log date and time in UTC and file + line number from where log was generated
- Used `lumberjack` package to setup log rotation
- Created middleware to log information about API requests such as log level, request method, request path, response time 

### Authentication and Authorization
- Used Google OAuth to authenticate API requests
- Short-lived access token and long-lived refresh token is created via JWT
- Tokens are generated on login
- Tokens are rotated on call to `/refresh`
- Tokens are invalidated on logout