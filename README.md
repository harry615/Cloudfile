# Cloudfile

Had to change require_secure_transport=OFF

Running on mobile network as uob_guest does not allow all ports that are required 
Need 0.0.0.0 in the docker file as uvicorn binds to 127.0.0.1 by default which restricts fastapi to accept connections only from docker , preventing my browser from accessing despite the correct port mapping

- Containerized in docker , Azure connection string and database url now saved locally in a .env
- Added the ability to manipulate files (Upload , list , download , delete , share) stored in azure blob storage
- Added E2EE encryption on backend for testing
- Front end built
- File sharing without encryption
- Shared files deletion from sender/receiver 
- Download (no encryption)
- Add front end keys built from user .
- File sharing links etc

Nice to haves for future updates :
- Deploy FastAPI backend on Azure App Service
- Deploy React frontend on Azure Static Web Apps

