# Swagger API Documentation

## Overview

This project includes comprehensive Swagger/OpenAPI 3 documentation for all authentication endpoints. The interactive documentation allows you to explore, understand, and test all API endpoints directly from your browser.

## Accessing Swagger UI

Once the application is running, you can access the Swagger UI at:

- **Swagger UI**: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)
- **OpenAPI JSON**: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)

## How to Use Swagger UI

### 1. Explore API Endpoints

The Swagger UI provides:
- Complete list of all available endpoints
- Request/response schemas with examples
- Detailed parameter descriptions
- HTTP status codes and error responses

### 2. Test JWT Authentication Flow

**Step 1: Register a New User**
1. Find the `POST /api/auth/register` endpoint
2. Click "Try it out"
3. Enter sample user data:
   ```json
   {
     "email": "test@example.com",
     "password": "testPassword123",
     "nickname": "TestUser"
   }
   ```
4. Click "Execute"
5. Copy the `accessToken` from the response

**Step 2: Authorize with JWT Token**
1. Click the 🔒 **Authorize** button at the top of the page
2. Enter: `Bearer YOUR_ACCESS_TOKEN_HERE`
3. Click **Authorize**
4. Click **Close**

**Step 3: Test Protected Endpoints**
- Now you can test endpoints that require authentication
- The JWT token will be automatically included in all requests

### 3. Test Token Refresh

1. Use the `POST /api/auth/refresh` endpoint
2. Provide the `refreshToken` from your login/register response
3. Get new tokens and update your authorization

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user account
- `POST /api/auth/login` - Authenticate existing user
- `POST /api/auth/refresh` - Refresh JWT tokens

### User Management
- `GET /api/auth/profile/{userId}` - Get user profile (requires authentication)

### Validation
- `GET /api/auth/check-email` - Check email availability

## Security Features

- **JWT Bearer Token Authentication**: Stateless authentication using JSON Web Tokens
- **Access & Refresh Tokens**: Separate tokens for API access and token renewal
- **BCrypt Password Encryption**: Secure password storage
- **Comprehensive Validation**: Input validation with detailed error messages

## Example Usage

### Register and Login Flow

1. **Register**: `POST /api/auth/register`
2. **Receive Tokens**: Get both access and refresh tokens
3. **Use Access Token**: Include in Authorization header for API calls
4. **Refresh When Needed**: Use refresh token to get new access tokens

### Authorization Header Format

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Development Notes

- Access tokens expire in 24 hours
- Refresh tokens expire in 7 days
- All tokens are signed with HMAC-SHA256
- Passwords are encrypted with BCrypt
- Email addresses must be unique

## Troubleshooting

**Token Expired Error**: Use the refresh token endpoint to get new tokens
**Authentication Failed**: Ensure you're using the correct Bearer token format
**Validation Errors**: Check the detailed error messages in responses

## Production Considerations

- Change JWT secret in production environment
- Enable HTTPS for all API communication
- Implement rate limiting for authentication endpoints
- Consider shorter token expiration times for enhanced security