package events

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"math/rand/v2"
)

// motion captcha geometry, in noise blocks. large blocks moving one block per frame at 10 fps keep the
// motion readable after telegram transcodes the gif to H.264
const (
	mcBlock      = 6  // block size in pixels
	mcGlyphScale = 4  // blocks per font cell, also the stroke width
	mcGap        = 6  // between digits
	mcMargin     = 10 // around the code
	mcJitter     = 3  // max random vertical shift of each digit
	mcFrames     = 30
	mcDelay      = 10 // frame delay, in 1/100 s
)

// mcFont is a 5x7 bitmap font for digits
var mcFont = [10][7]string{
	{"01110", "10001", "10011", "10101", "11001", "10001", "01110"},
	{"00100", "01100", "00100", "00100", "00100", "00100", "01110"},
	{"01110", "10001", "00001", "00010", "00100", "01000", "11111"},
	{"11110", "00001", "00001", "01110", "00001", "00001", "11110"},
	{"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
	{"11111", "10000", "11110", "00001", "00001", "10001", "01110"},
	{"00110", "01000", "10000", "11110", "10001", "10001", "01110"},
	{"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
	{"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	{"01110", "10001", "10001", "01111", "00001", "00010", "01100"},
}

// renderMotionCaptcha draws the digits as an animated gif made of black and white noise. noise inside the
// digits scrolls down, noise outside scrolls up, so a viewer sees the digits while it plays, but every
// single frame is uniform noise with nothing to read: a model that looks at frames as still images, or at
// their average, gets no answer. both noise fields are independent and never repeat within the animation,
// so no frame carries a boundary between them either.
func renderMotionCaptcha(code string) ([]byte, error) {
	glyphW, glyphH := 5*mcGlyphScale, 7*mcGlyphScale
	w := 2*mcMargin + len(code)*glyphW + (len(code)-1)*mcGap
	h := 2*mcMargin + glyphH

	mask := make([][]bool, h)
	for y := range mask {
		mask[y] = make([]bool, w)
	}
	for i, ch := range code {
		if ch < '0' || ch > '9' {
			return nil, fmt.Errorf("motion captcha supports digits only, got %q", code)
		}
		x0 := mcMargin + i*(glyphW+mcGap)
		y0 := mcMargin + rand.IntN(2*mcJitter+1) - mcJitter //nolint:gosec // layout noise, not a secret
		for row, bits := range mcFont[ch-'0'] {
			for col, bit := range bits {
				if bit != '1' {
					continue
				}
				for dy := range mcGlyphScale {
					for dx := range mcGlyphScale {
						if y := y0 + row*mcGlyphScale + dy; y >= 0 && y < h {
							mask[y][x0+col*mcGlyphScale+dx] = true
						}
					}
				}
			}
		}
	}

	noise := func() [][]bool {
		res := make([][]bool, h+mcFrames)
		for y := range res {
			res[y] = make([]bool, w)
			for x := range res[y] {
				res[y][x] = rand.IntN(2) == 1 //nolint:gosec // visual noise, not a secret
			}
		}
		return res
	}
	fg, bg := noise(), noise()

	palette := color.Palette{color.Black, color.White}
	anim := &gif.GIF{LoopCount: 0}
	for f := range mcFrames {
		img := image.NewPaletted(image.Rect(0, 0, w*mcBlock, h*mcBlock), palette)
		for y := range h {
			for x := range w {
				// fg row y-f+frames moves down as f grows, bg row y+f moves up
				on := bg[y+f][x]
				if mask[y][x] {
					on = fg[y-f+mcFrames][x]
				}
				if !on {
					continue
				}
				for py := y * mcBlock; py < (y+1)*mcBlock; py++ {
					for px := x * mcBlock; px < (x+1)*mcBlock; px++ {
						img.SetColorIndex(px, py, 1)
					}
				}
			}
		}
		anim.Image = append(anim.Image, img)
		anim.Delay = append(anim.Delay, mcDelay)
	}

	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, anim); err != nil {
		return nil, fmt.Errorf("failed to encode motion captcha: %w", err)
	}
	return buf.Bytes(), nil
}
