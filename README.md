`Rest Weather Go` is a native Go implementation of the WeatherAPI, built to practice REST API fundamentals and other best practices for production-grade Go REST applications.

### Authentication and Authorization
- Used Google OAuth to authenticate API requests
- Short-lived access token and long-lived refresh token is created via JWT
- Tokens are generated on login
- Tokens are rotated on call to `refresh`
- Tokens are invalidated on logout