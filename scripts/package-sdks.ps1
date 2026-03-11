<#
.SYNOPSIS
    Builds and packages all Airlock Gateway SDKs.

.DESCRIPTION
    Supports building individual SDKs or all at once.
    Outputs packages to dist/{language}/

.PARAMETER Sdk
    Which SDK to build: dotnet, python, typescript, go, rust, or all.

.PARAMETER Version
    Package version (default: 0.1.0).

.PARAMETER NuGetApiKey
    API key for pushing to nuget.org.

.PARAMETER PyPiToken
    API token for uploading to PyPI.

.PARAMETER NpmToken
    NPM auth token for publishing.

.PARAMETER CratesToken
    API token for crates.io.

.PARAMETER Push
    If set, pushes packages to their respective registries.

.EXAMPLE
    .\package-sdks.ps1 -Sdk all -Version 0.2.0
    .\package-sdks.ps1 -Sdk dotnet -Push -NuGetApiKey "your-key"
#>

param(
    [ValidateSet("dotnet", "python", "typescript", "go", "rust", "all")]
    [string]$Sdk = "all",

    [string]$Version = "0.1.0",

    [string]$NuGetApiKey,
    [string]$PyPiToken,
    [string]$NpmToken,
    [string]$CratesToken,

    [switch]$Push
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$SrcRoot = Join-Path $Root "src"
$DistRoot = Join-Path $Root "dist"

function Write-Step($msg) {
    Write-Host "`n===> $msg" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "  [WARN] $msg" -ForegroundColor Yellow
}

# ── .NET ─────────────────────────────────────────────────────────

function Build-DotNet {
    Write-Step "Building .NET SDK v$Version"

    $proj = Join-Path $SrcRoot "dotnet\Airlock.Gateway.Sdk\Airlock.Gateway.Sdk.csproj"
    $testProj = Join-Path $SrcRoot "dotnet\Airlock.Gateway.Sdk.Tests\Airlock.Gateway.Sdk.Tests.csproj"
    $outDir = Join-Path $DistRoot "dotnet"

    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    # Build
    dotnet build $proj -c Release /p:Version=$Version
    if ($LASTEXITCODE -ne 0) { throw ".NET build failed" }

    # Test
    dotnet test $testProj -c Release --no-build --verbosity normal
    if ($LASTEXITCODE -ne 0) { throw ".NET tests failed" }

    # Pack
    dotnet pack $proj -c Release /p:Version=$Version -o $outDir
    if ($LASTEXITCODE -ne 0) { throw ".NET pack failed" }

    Write-Success "NuGet package created in $outDir"

    if ($Push -and $NuGetApiKey) {
        Write-Step "Pushing to nuget.org"
        $nupkg = Get-ChildItem $outDir -Filter "*.nupkg" | Select-Object -First 1
        dotnet nuget push $nupkg.FullName --api-key $NuGetApiKey --source https://api.nuget.org/v3/index.json
        if ($LASTEXITCODE -ne 0) { throw "NuGet push failed" }
        Write-Success "Pushed to nuget.org"
    }
    elseif ($Push) {
        Write-Warn "NuGet push skipped: -NuGetApiKey not provided"
    }
}

# ── Python ───────────────────────────────────────────────────────

function Build-Python {
    Write-Step "Building Python SDK v$Version"

    $pyDir = Join-Path $SrcRoot "python"
    $outDir = Join-Path $DistRoot "python"

    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Push-Location $pyDir
    try {
        # Update version in pyproject.toml
        $content = Get-Content "pyproject.toml" -Raw
        $content = $content -replace 'version = "[^"]*"', "version = `"$Version`""
        Set-Content "pyproject.toml" $content

        # Install deps and run tests
        pip install -e ".[dev]" --quiet
        if ($LASTEXITCODE -ne 0) { throw "Python install failed" }

        pytest --tb=short
        if ($LASTEXITCODE -ne 0) { throw "Python tests failed" }

        # Build wheel and sdist
        pip install build --quiet
        python -m build --outdir $outDir
        if ($LASTEXITCODE -ne 0) { throw "Python build failed" }

        Write-Success "Python packages created in $outDir"

        if ($Push -and $PyPiToken) {
            Write-Step "Uploading to PyPI"
            pip install twine --quiet
            $env:TWINE_USERNAME = "__token__"
            $env:TWINE_PASSWORD = $PyPiToken
            twine upload "$outDir/*"
            if ($LASTEXITCODE -ne 0) { throw "PyPI upload failed" }
            Write-Success "Uploaded to PyPI"
        }
        elseif ($Push) {
            Write-Warn "PyPI upload skipped: -PyPiToken not provided"
        }
    }
    finally {
        Pop-Location
    }
}

# ── TypeScript ───────────────────────────────────────────────────

function Build-TypeScript {
    Write-Step "Building TypeScript SDK v$Version"

    $tsDir = Join-Path $SrcRoot "typescript"
    $outDir = Join-Path $DistRoot "typescript"

    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Push-Location $tsDir
    try {
        # Update version in package.json
        $pkg = Get-Content "package.json" -Raw | ConvertFrom-Json
        $pkg.version = $Version
        $pkg | ConvertTo-Json -Depth 10 | Set-Content "package.json"

        # Install, build, test
        npm install --silent
        if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

        npm run build
        if ($LASTEXITCODE -ne 0) { throw "TypeScript build failed" }

        npm test
        if ($LASTEXITCODE -ne 0) { throw "TypeScript tests failed" }

        # Pack
        npm pack --pack-destination $outDir
        if ($LASTEXITCODE -ne 0) { throw "npm pack failed" }

        Write-Success "NPM package created in $outDir"

        if ($Push -and $NpmToken) {
            Write-Step "Publishing to NPM"
            $env:NPM_TOKEN = $NpmToken
            npm publish --access public
            if ($LASTEXITCODE -ne 0) { throw "npm publish failed" }
            Write-Success "Published to NPM"
        }
        elseif ($Push) {
            Write-Warn "NPM publish skipped: -NpmToken not provided"
        }
    }
    finally {
        Pop-Location
    }
}

# ── Go ───────────────────────────────────────────────────────────

function Build-Go {
    Write-Step "Building Go SDK v$Version"

    $goDir = Join-Path $SrcRoot "go"

    Push-Location $goDir
    try {
        # Test
        go test ./airlock/... -v
        if ($LASTEXITCODE -ne 0) { throw "Go tests failed" }

        Write-Success "Go tests passed"
        Write-Host "  Go packages are published by tagging the repository:" -ForegroundColor Gray
        Write-Host "    git tag src/go/v$Version" -ForegroundColor Gray
        Write-Host "    git push origin src/go/v$Version" -ForegroundColor Gray

        if ($Push) {
            Write-Step "Tagging Go module v$Version"
            git tag "src/go/v$Version"
            Write-Success "Tagged src/go/v$Version (push manually with 'git push origin src/go/v$Version')"
        }
    }
    finally {
        Pop-Location
    }
}

# ── Rust ─────────────────────────────────────────────────────────

function Build-Rust {
    Write-Step "Building Rust SDK v$Version"

    $rustDir = Join-Path $SrcRoot "rust"
    $outDir = Join-Path $DistRoot "rust"

    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Push-Location $rustDir
    try {
        # Auto-detect MSVC LIB paths on Windows if not already set
        if ($IsWindows -or $env:OS -eq "Windows_NT") {
            if (-not $env:LIB) {
                Write-Host "  Detecting MSVC lib paths..." -ForegroundColor Gray

                # Find VC Tools lib directory
                $vcLib = Get-ChildItem "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter "msvcrt.lib" -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -like "*\x64\*" } |
                    Select-Object -First 1 -ExpandProperty DirectoryName

                # Find Windows SDK ucrt and um lib directories
                $sdkBase = "C:\Program Files (x86)\Windows Kits\10\Lib"
                $sdkVersion = Get-ChildItem $sdkBase -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
                $ucrtLib = Join-Path $sdkBase "$sdkVersion\ucrt\x64"
                $umLib = Join-Path $sdkBase "$sdkVersion\um\x64"

                $libPaths = @($vcLib, $ucrtLib, $umLib) | Where-Object { $_ -and (Test-Path $_) }

                if ($libPaths.Count -ge 2) {
                    $env:LIB = $libPaths -join ";"
                    Write-Host "  Set LIB=$($env:LIB)" -ForegroundColor Gray
                }
                else {
                    Write-Warn "Could not auto-detect MSVC paths. Run from VS Developer PowerShell or set LIB manually."
                }
            }
        }

        # Update version in Cargo.toml
        $content = Get-Content "Cargo.toml" -Raw
        $content = $content -replace 'version = "[^"]*"', "version = `"$Version`""
        Set-Content "Cargo.toml" $content

        # Build and test
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }

        cargo test
        if ($LASTEXITCODE -ne 0) { throw "Rust tests failed" }

        # Package
        cargo package --allow-dirty
        if ($LASTEXITCODE -ne 0) { throw "Rust package failed" }

        # Copy .crate file to dist
        $crateFile = Get-ChildItem "target\package" -Filter "*.crate" | Select-Object -First 1
        if ($crateFile) {
            Copy-Item $crateFile.FullName $outDir
        }

        Write-Success "Rust crate packaged in $outDir"

        if ($Push -and $CratesToken) {
            Write-Step "Publishing to crates.io"
            cargo publish --token $CratesToken
            if ($LASTEXITCODE -ne 0) { throw "crates.io publish failed" }
            Write-Success "Published to crates.io"
        }
        elseif ($Push) {
            Write-Warn "crates.io publish skipped: -CratesToken not provided"
        }
    }
    finally {
        Pop-Location
    }
}

# ── Main ─────────────────────────────────────────────────────────

Write-Host "Airlock Gateway SDK Packager" -ForegroundColor Magenta
Write-Host "Version: $Version | Target: $Sdk | Push: $Push"

$sdks = if ($Sdk -eq "all") { @("dotnet", "python", "typescript", "go", "rust") } else { @($Sdk) }

foreach ($s in $sdks) {
    switch ($s) {
        "dotnet"     { Build-DotNet }
        "python"     { Build-Python }
        "typescript" { Build-TypeScript }
        "go"         { Build-Go }
        "rust"       { Build-Rust }
    }
}

Write-Host "`n====================================" -ForegroundColor Magenta
Write-Host "All done!" -ForegroundColor Green
if (-not $Push) {
    Write-Host "Packages are in: $DistRoot" -ForegroundColor Gray
    Write-Host "Use -Push to upload to registries." -ForegroundColor Gray
}
