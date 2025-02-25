# fastapi_to_azure
Moving from a sqlite database to an azure hosted sql database


Had to change require_secure_transport=OFF

Running on mobile network as uob_guest does not allow all ports that are required 

Need 0.0.0.0 in the docker file as uvicorn binds to 127.0.0.1 by default which restricts fastapi to accept connections only from docker , preventing my browser from accessing despite the correct port mapping
