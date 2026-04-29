@echo off
echo Starting Zimbabwe Network SSL & SNI Scanner...
echo.
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting the web application...
echo.
echo The scanner will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.
python app.py
