param(
    [string]$AssetDirectory = (Join-Path $PSScriptRoot '..\assets')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$AssetDirectory = [System.IO.Path]::GetFullPath($AssetDirectory)
[System.IO.Directory]::CreateDirectory($AssetDirectory) | Out-Null
$edge = 1024
$scale = $edge / 512.0
$bitmap = [System.Drawing.Bitmap]::new(
    $edge,
    $edge,
    [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality

function Pt([float]$x, [float]$y) {
    return [System.Drawing.PointF]::new($x * $script:scale, $y * $script:scale)
}

function New-RoundPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $d = $r * 2.0 * $script:scale
    $x *= $script:scale; $y *= $script:scale
    $w *= $script:scale; $h *= $script:scale
    $path.AddArc($x, $y, $d, $d, 180, 90)
    $path.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $path.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $path.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

try {
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $tile = New-RoundPath 10 10 492 492 112
    $background = [System.Drawing.SolidBrush]::new(
        [System.Drawing.Color]::FromArgb(255, 20, 23, 28)
    )
    $graphics.FillPath($background, $tile)

    # Duetto: the left (blue) and right (orange) speaker rings overlap; the
    # white lens between them is the phantom centre a calibrated pair creates.
    $leftPen = [System.Drawing.Pen]::new(
        [System.Drawing.Color]::FromArgb(255, 61, 140, 245), 40 * $scale
    )
    $rightPen = [System.Drawing.Pen]::new(
        [System.Drawing.Color]::FromArgb(255, 255, 138, 61), 40 * $scale
    )
    $graphics.DrawEllipse($leftPen, 102 * $scale, 152 * $scale, 208 * $scale, 208 * $scale)
    $graphics.DrawEllipse($rightPen, 202 * $scale, 152 * $scale, 208 * $scale, 208 * $scale)
    # Arc angles of the two intersection points (256, 256 +/- 91.2).
    $lens = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $lens.AddArc(102 * $scale, 152 * $scale, 208 * $scale, 208 * $scale, -61.3, 122.6)
    $lens.AddArc(202 * $scale, 152 * $scale, 208 * $scale, 208 * $scale, 118.7, 122.6)
    $lens.CloseFigure()
    $white = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
    $graphics.FillPath($white, $lens)

    $masterPath = Join-Path $AssetDirectory 'airbridge-512.png'
    $bitmap.Save($masterPath, [System.Drawing.Imaging.ImageFormat]::Png)

    $pngFrames = [System.Collections.Generic.List[byte[]]]::new()
    $sizes = @(16, 24, 32, 48, 64, 128, 256)
    foreach ($size in $sizes) {
        $frame = [System.Drawing.Bitmap]::new($size, $size,
            [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $fg = [System.Drawing.Graphics]::FromImage($frame)
        $fg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $fg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $fg.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $fg.DrawImage($bitmap, 0, 0, $size, $size)
        $fg.Dispose()
        $stream = [System.IO.MemoryStream]::new()
        $frame.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngFrames.Add($stream.ToArray())
        $stream.Dispose(); $frame.Dispose()
    }

    $ico = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($ico)
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $size = $sizes[$i]
        $dim = if ($size -ge 256) { [byte]0 } else { [byte]$size }
        $writer.Write($dim); $writer.Write($dim)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$pngFrames[$i].Length)
        $writer.Write([uint32]$offset)
        $offset += $pngFrames[$i].Length
    }
    foreach ($frameBytes in $pngFrames) { $writer.Write($frameBytes) }
    $writer.Flush()
    [System.IO.File]::WriteAllBytes((Join-Path $AssetDirectory 'airbridge.ico'), $ico.ToArray())
    $writer.Dispose(); $ico.Dispose()

    $tile.Dispose(); $background.Dispose()
    $leftPen.Dispose(); $rightPen.Dispose(); $lens.Dispose(); $white.Dispose()
    Write-Output "Created Duetto icon assets in $AssetDirectory"
}
finally {
    $graphics.Dispose(); $bitmap.Dispose()
}
