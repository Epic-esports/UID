# Use Python 3.10
FROM python:3.10-slim

# Install system dependencies needed for mitmproxy
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the folder inside the container
WORKDIR /app

# Copy all your files into the container
COPY . .

# Install the Python libraries
RUN pip install --no-cache-dir -r requirements.txt

# Open port 8080 for the proxy
EXPOSE 8080

# Run your script (Replace 'your_script_name.py' with the actual name of your file)
CMD ["python", "main.py"]
