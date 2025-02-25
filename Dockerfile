# Use an official Python runtime as the base image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container
COPY . .

# Expose the port your app runs on
EXPOSE 8000

# Run the application , the 0.0.0.0 is needed for docker to work 
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]