@echo off
REM Comprehensive Backend API Test Suite
REM Tests all endpoints with positive and negative cases

setlocal enabledelayedexpansion

echo ========================================
echo Stegosaurust Backend API Test Suite
echo ========================================
echo.

set BASE_URL=http://localhost:8080
set TOKEN=
set CAPTCHA_ID=
set MESSAGE_ID=

echo [TEST 1] Health Check
curl.exe -s %BASE_URL%/health
echo.
echo.

echo [TEST 2] Get Captcha
for /f "delims=" %%i in ('curl.exe -s %BASE_URL%/api/captcha') do set CAPTCHA_RESPONSE=%%i
echo %CAPTCHA_RESPONSE%
echo.
echo.

echo [TEST 3] Register User (Positive)
echo Note: Captcha answer needs to be read from the image, using placeholder
curl.exe -s -X POST %BASE_URL%/api/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser%RANDOM%\",\"email\":\"test%RANDOM%@example.com\",\"password\":\"SecurePass123\",\"captcha_id\":\"test\",\"captcha_answer\":\"test\"}"
echo.
echo.

echo [TEST 4] Register User (Negative - Short Password)
curl.exe -s -X POST %BASE_URL%/api/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser2\",\"email\":\"test2@example.com\",\"password\":\"short\",\"captcha_id\":\"test\",\"captcha_answer\":\"test\"}"
echo.
echo.

echo [TEST 5] Register User (Negative - Invalid Email)
curl.exe -s -X POST %BASE_URL%/api/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser3\",\"email\":\"notanemail\",\"password\":\"SecurePass123\",\"captcha_id\":\"test\",\"captcha_answer\":\"test\"}"
echo.
echo.

echo [TEST 6] Login (Negative - No Captcha)
curl.exe -s -X POST %BASE_URL%/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123\",\"captcha_id\":\"invalid\",\"captcha_answer\":\"wrong\"}"
echo.
echo.

echo [TEST 7] Access Protected Endpoint Without Token (Negative)
curl.exe -s -X POST %BASE_URL%/api/encrypt ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"secret\",\"seed_words\":\"test\"}"
echo.
echo.

echo [TEST 8] Access Protected Endpoint With Invalid Token (Negative)
curl.exe -s -X POST %BASE_URL%/api/encrypt ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer invalid_token_here" ^
  -d "{\"text\":\"secret\",\"seed_words\":\"test\"}"
echo.
echo.

echo [TEST 9] Encrypt With Empty Text (Negative)
curl.exe -s -X POST %BASE_URL%/api/encrypt ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -d "{\"text\":\"\",\"seed_words\":\"test\"}"
echo.
echo.

echo [TEST 10] Decrypt With Wrong Seed Words (Negative)
curl.exe -s -X POST %BASE_URL%/api/decrypt ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -d "{\"encrypted_data\":\"somedata\",\"seed_words\":\"wrong_seed\"}"
echo.
echo.

echo [TEST 11] Generate QR Code With Too Long Data (Negative)
set LONG_DATA=
for /l %%i in (1,1,100) do set LONG_DATA=!LONG_DATA!0123456789
curl.exe -s -X POST %BASE_URL%/api/qrcode/generate ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -d "{\"data\":\"!LONG_DATA!\",\"size\":256}"
echo.
echo.

echo [TEST 12] Get User Profile Without Token (Negative)
curl.exe -s %BASE_URL%/api/user/profile
echo.
echo.

echo [TEST 13] Delete Non-Existent Message (Negative)
curl.exe -s -X DELETE %BASE_URL%/api/messages/nonexistent-id ^
  -H "Authorization: Bearer %TOKEN%"
echo.
echo.

echo ========================================
echo Test Suite Complete
echo ========================================
echo.
echo Note: Some tests require valid JWT token from successful login
echo To run full test suite, manually complete registration/login first
