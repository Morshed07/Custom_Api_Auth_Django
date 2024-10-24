FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install any dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy the current directory contents into the container
COPY . /app/

# Expose port 8000 for the Django app
EXPOSE 8000

# Set environment variables to prevent interactive prompts during install
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Run migrations and start the development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
