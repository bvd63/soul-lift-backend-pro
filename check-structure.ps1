# PowerShell version of check-structure.sh
$must_have = @(
    "index.js",
    "package.json", 
    "render.yaml",
    "db/migrate.sql",
    "data/ai_quotes.json",
    "categories.json",
    "src/routes/aiPersonalization.js",
    "src/routes/aiRecommendations.js",
    "src/utils/logger.js",
    "src/utils/respond.js",
    "src/utils/validator.js",
    "src/utils/apiRetry.js",
    "src/utils/cache.js",
    "src/utils/memoryCache.js",
    "src/services/redisClient.js",
    "src/jobs/supervisor.js",
    "src/config/validateEnv.js",
    ".gitignore",
    ".env",
    "Dockerfile"
)

$missing = 0
foreach ($f in $must_have) {
    if (Test-Path $f) {
        Write-Host "✅ $f" -ForegroundColor Green
    } else {
        Write-Host "❌ Missing: $f" -ForegroundColor Red
        $missing = 1
    }
}

if ($missing -eq 0) {
    Write-Host "`n🎉 All required files are present!" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Some required files are missing!" -ForegroundColor Yellow
}

exit $missing
