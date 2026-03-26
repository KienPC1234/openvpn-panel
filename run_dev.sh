#!/bin/bash

# Script to run all VPN Panel microservices for development
# Usage: ./run_dev.sh

PID_DIR="./pids"
mkdir -p $PID_DIR

# Function to stop all services on Ctrl+C
cleanup() {
    echo ""
    echo "Stopping all services..."
    [ -f $PID_DIR/tailwind.pid ] && kill $(cat $PID_DIR/tailwind.pid) 2>/dev/null
    [ -f $PID_DIR/django.pid ] && kill $(cat $PID_DIR/django.pid) 2>/dev/null
    
    # Celery usually handles its own pids via --pidfile
    pkill -f "celery -A vpn_project"
    
    rm -rf $PID_DIR
    exit
}

trap cleanup SIGINT SIGTERM EXIT

echo "------------------------------------------------"
echo "🚀 Starting VPN Panel Development Environment"
echo "------------------------------------------------"

# 0. Kill existing processes on port 8000
echo "🧹 Cleaning up port 8000..."
fuser -k 8000/tcp 2>/dev/null

# 1. Start Tailwind CSS Watcher (Live compile)
echo "🎨 Starting Tailwind Watcher..."
python manage.py tailwind start &
echo $! > $PID_DIR/tailwind.pid

# 2. Start Celery Worker (Background tasks)
echo "👷 Starting Celery Worker..."
celery -A vpn_project worker -l info --pidfile=$PID_DIR/worker.pid &

# 3. Start Celery Beat (Periodic tasks)
echo "⏰ Starting Celery Beat..."
celery -A vpn_project beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler --pidfile=$PID_DIR/beat.pid &

# 4. Start Django Development Server
echo "🌐 Starting Django Server at http://localhost:8000"
python manage.py runserver 0.0.0.0:8000 &
echo $! > $PID_DIR/django.pid

# Wait for all processes to finish
wait
