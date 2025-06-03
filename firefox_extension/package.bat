@echo off
echo Packaging Kasm Secure Browser Launcher extension...

REM Create a temporary directory for packaging
if exist temp_package rmdir /s /q temp_package
mkdir temp_package

REM Copy all necessary files to the temp directory
xcopy /y manifest.json temp_package\
xcopy /y background.js temp_package\
xcopy /y /s icons temp_package\icons\

REM Create the XPI file (which is just a ZIP file with .xpi extension)
cd temp_package
powershell -Command "Compress-Archive -Path * -DestinationPath ..\kasm_secure_browser.xpi -Force"
cd ..

REM Clean up the temporary directory
rmdir /s /q temp_package

echo Extension packaged as kasm_secure_browser.xpi
echo.
echo To install in Firefox:
echo 1. Open Firefox and go to about:addons
echo 2. Click the gear icon and select "Install Add-on From File..."
echo 3. Select the kasm_secure_browser.xpi file