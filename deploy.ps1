# Event Mill - Build & Deploy to Cloud Run
# Usage: .\deploy.ps1

param(
    [string]$Project = "your-project-id",
    [string]$Region = "us-central1",
    [string]$Service = "event-mill",
    [string]$BuildConfig = "build-event-mill.yaml"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Event Mill - Cloud Run Deploy ===" -ForegroundColor Cyan
Write-Host "Project: $Project" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host "Service: $Service" -ForegroundColor Yellow
Write-Host ""

# Step 1: Build Docker image
Write-Host "Step 1: Building Docker image..." -ForegroundColor Green
gcloud builds submit "--project=$Project" "--config=$BuildConfig" .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build successful" -ForegroundColor Green
Write-Host ""

# Step 2: Deploy to Cloud Run
Write-Host "Step 2: Deploying to Cloud Run..." -ForegroundColor Green
$ImageUri = $Region + "-docker.pkg.dev/" + $Project + "/eventmill/" + $Service + ":latest"
$ServiceAccount = "eventmill-runner@" + $Project + ".iam.gserviceaccount.com"
$BucketPrefix = if ($env:EVENTMILL_BUCKET_PREFIX) { $env:EVENTMILL_BUCKET_PREFIX } else { "$Project-eventmill" }
Write-Host "  Image: $ImageUri" -ForegroundColor Yellow
Write-Host "  Bucket prefix: $BucketPrefix" -ForegroundColor Yellow

gcloud run deploy $Service "--region=$Region" "--project=$Project" "--image=$ImageUri" "--platform=managed" "--port=8080" "--memory=1Gi" "--cpu=2" "--timeout=3600" "--min-instances=0" "--max-instances=3" "--concurrency=10" "--service-account=$ServiceAccount" "--set-env-vars=EVENTMILL_BUCKET_PREFIX=$BucketPrefix,EVENTMILL_LOG_LEVEL=INFO" "--allow-unauthenticated"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Deployment failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Deployment successful" -ForegroundColor Green
Write-Host ""
Write-Host "Service URL:" -ForegroundColor Cyan
$fmt = "value(status.url)"
gcloud run services describe $Service "--region=$Region" "--project=$Project" "--format=$fmt"
