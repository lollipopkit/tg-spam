package events

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"math/rand/v2"
)

// motionStyle sets the geometry and timing of the motion captcha. sizes other than block are in noise blocks
type motionStyle struct {
	block  int // block size in pixels
	scale  int // blocks per font cell, also the stroke width
	gap    int // between digits
	margin int // around the code
	jitter int // max random vertical shift of each digit
	frames int
	delay  int // frame delay, in 1/100 s
}

// captchaStyle is the style in use, picked by comparing variants in real telegram clients. large blocks and
// bold digits moving one block per frame keep the motion readable after telegram transcodes the gif to H.264
func captchaStyle() motionStyle {
	return motionStyle{block: 6, scale: 6, gap: 6, margin: 10, jitter: 3, frames: 30, delay: 8}
}

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
	return renderMotion(code, captchaStyle())
}

func renderMotion(code string, st motionStyle) ([]byte, error) {
	glyphW, glyphH := 5*st.scale, 7*st.scale
	w := 2*st.margin + len(code)*glyphW + (len(code)-1)*st.gap
	h := 2*st.margin + glyphH

	mask := make([][]bool, h)
	for y := range mask {
		mask[y] = make([]bool, w)
	}
	for i, ch := range code {
		if ch < '0' || ch > '9' {
			return nil, fmt.Errorf("motion captcha supports digits only, got %q", code)
		}
		x0 := st.margin + i*(glyphW+st.gap)
		y0 := st.margin + rand.IntN(2*st.jitter+1) - st.jitter //nolint:gosec // layout noise, not a secret
		for row, bits := range mcFont[ch-'0'] {
			for col, bit := range bits {
				if bit != '1' {
					continue
				}
				for dy := range st.scale {
					for dx := range st.scale {
						if y := y0 + row*st.scale + dy; y >= 0 && y < h {
							mask[y][x0+col*st.scale+dx] = true
						}
					}
				}
			}
		}
	}

	noise := func() [][]bool {
		res := make([][]bool, h+st.frames)
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
	for f := range st.frames {
		img := image.NewPaletted(image.Rect(0, 0, w*st.block, h*st.block), palette)
		for y := range h {
			for x := range w {
				// fg row y-f+frames moves down as f grows, bg row y+f moves up
				on := bg[y+f][x]
				if mask[y][x] {
					on = fg[y-f+st.frames][x]
				}
				if !on {
					continue
				}
				for py := y * st.block; py < (y+1)*st.block; py++ {
					for px := x * st.block; px < (x+1)*st.block; px++ {
						img.SetColorIndex(px, py, 1)
					}
				}
			}
		}
		anim.Image = append(anim.Image, img)
		anim.Delay = append(anim.Delay, st.delay)
	}

	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, anim); err != nil {
		return nil, fmt.Errorf("failed to encode motion captcha: %w", err)
	}
	return buf.Bytes(), nil
}
