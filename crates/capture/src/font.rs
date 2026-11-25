//! Font loading, measurement, and anti-aliased glyph rendering onto `tiny_skia::Pixmap`.

use ab_glyph::{Font, FontVec, GlyphId, PxScale, ScaleFont};
use tiny_skia::{Color, Pixmap};

const CANDIDATE_FONTS: &[&str] = &[
    "/usr/share/fonts/truetype/roboto/Roboto-Medium.ttf",
    "/usr/share/fonts/truetype/roboto/Roboto-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
];

/// Renders UI text using an installed TrueType font with a built-in 5x7 ASCII fallback.
pub struct FontRenderer {
    font: Option<FontVec>,
}

impl FontRenderer {
    /// Loads the first available system UI font.
    pub fn load() -> Self {
        for path in CANDIDATE_FONTS {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(font) = FontVec::try_from_vec(bytes) {
                    return Self { font: Some(font) };
                }
            }
        }
        Self { font: None }
    }

    /// Measures `(width, height)` in pixels for `text` at font size `px`.
    pub fn measure_text(&self, text: &str, px: f32) -> (f32, f32) {
        let Some(font) = &self.font else {
            return measure_bitmap_text(text, px);
        };
        let scaled = font.as_scaled(PxScale::from(px));
        let mut width = 0.0_f32;
        let mut prev: Option<GlyphId> = None;
        for ch in text.chars() {
            let gid = font.glyph_id(ch);
            if let Some(p) = prev {
                width += scaled.kern(p, gid);
            }
            width += scaled.h_advance(gid);
            prev = Some(gid);
        }
        let height = (scaled.ascent() - scaled.descent()).max(px);
        (width, height)
    }

    /// Draws `text` with top-left box `(x, y)` at size `px` in `color`.
    pub fn draw_text(&self, pixmap: &mut Pixmap, x: f32, y: f32, px: f32, color: Color, text: &str) {
        let Some(font) = &self.font else {
            draw_bitmap_text(pixmap, x, y, px, color, text);
            return;
        };

        let scaled = font.as_scaled(PxScale::from(px));
        let baseline = y + scaled.ascent();
        let mut pen_x = x;
        let mut prev: Option<GlyphId> = None;

        for ch in text.chars() {
            let gid = font.glyph_id(ch);
            if let Some(p) = prev {
                pen_x += scaled.kern(p, gid);
            }
            let glyph = gid.with_scale_and_position(PxScale::from(px), ab_glyph::point(pen_x, baseline));
            if let Some(outlined) = font.outline_glyph(glyph) {
                let bounds = outlined.px_bounds();
                outlined.draw(|gx, gy, cov| {
                    if cov <= 0.004 {
                        return;
                    }
                    let px_x = bounds.min.x as i32 + gx as i32;
                    let px_y = bounds.min.y as i32 + gy as i32;
                    blend_pixel(pixmap, px_x, px_y, color, cov);
                });
            }
            pen_x += scaled.h_advance(gid);
            prev = Some(gid);
        }
    }

    /// Draws `text` centered inside the box `(x, y, w, h)`.
    pub fn draw_centered(
        &self,
        pixmap: &mut Pixmap,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        px: f32,
        color: Color,
        text: &str,
    ) {
        let (tw, th) = self.measure_text(text, px);
        let tx = x + (w - tw) * 0.5;
        let ty = y + (h - th) * 0.5;
        self.draw_text(pixmap, tx, ty, px, color, text);
    }

    /// Truncates `text` with `...` so it fits within `max_width` pixels.
    pub fn ellipsize(&self, text: &str, px: f32, max_width: f32) -> String {
        let (w, _) = self.measure_text(text, px);
        if w <= max_width {
            return text.to_string();
        }
        let mut out = String::new();
        for ch in text.chars() {
            let mut candidate = out.clone();
            candidate.push(ch);
            candidate.push_str("...");
            if self.measure_text(&candidate, px).0 > max_width {
                break;
            }
            out.push(ch);
        }
        if out.is_empty() {
            "...".to_string()
        } else {
            out.push_str("...");
            out
        }
    }
}

fn blend_pixel(pixmap: &mut Pixmap, x: i32, y: i32, color: Color, cov: f32) {
    if x < 0 || y < 0 {
        return;
    }
    let ux = x as u32;
    let uy = y as u32;
    if ux >= pixmap.width() || uy >= pixmap.height() {
        return;
    }
    let idx = ((uy * pixmap.width() + ux) * 4) as usize;
    let data = pixmap.data_mut();
    let sa = (color.alpha() * cov).clamp(0.0, 1.0);
    let inv = 1.0 - sa;
    let sr = color.red() * sa * 255.0;
    let sg = color.green() * sa * 255.0;
    let sb = color.blue() * sa * 255.0;

    data[idx] = (sr + data[idx] as f32 * inv).round().clamp(0.0, 255.0) as u8;
    data[idx + 1] = (sg + data[idx + 1] as f32 * inv).round().clamp(0.0, 255.0) as u8;
    data[idx + 2] = (sb + data[idx + 2] as f32 * inv).round().clamp(0.0, 255.0) as u8;
    data[idx + 3] = (sa * 255.0 + data[idx + 3] as f32 * inv)
        .round()
        .clamp(0.0, 255.0) as u8;
}

fn measure_bitmap_text(text: &str, px: f32) -> (f32, f32) {
    let scale = (px / 7.0).max(1.0);
    let count = text.chars().count() as f32;
    (count * 6.0 * scale, 7.0 * scale)
}

fn draw_bitmap_text(pixmap: &mut Pixmap, x: f32, y: f32, px: f32, color: Color, text: &str) {
    let scale = (px / 7.0).round().max(1.0) as i32;
    let mut pen_x = x.round() as i32;
    let top_y = y.round() as i32;
    for ch in text.chars() {
        let glyph = bitmap_glyph(ch);
        for (row, bits) in glyph.iter().enumerate() {
            for col in 0..5 {
                if (bits >> (4 - col)) & 1 == 1 {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            blend_pixel(
                                pixmap,
                                pen_x + col * scale + dx,
                                top_y + (row as i32) * scale + dy,
                                color,
                                1.0,
                            );
                        }
                    }
                }
            }
        }
        pen_x += 6 * scale;
    }
}

fn bitmap_glyph(ch: char) -> [u8; 7] {
    match ch.to_ascii_uppercase() {
        '0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        '1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        '2' => [0x0E, 0x11, 0x01, 0x06, 0x08, 0x10, 0x1F],
        '3' => [0x0E, 0x11, 0x01, 0x06, 0x01, 0x11, 0x0E],
        '4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        '5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        '6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        '7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        '9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        'D' => [0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E],
        'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        'G' => [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
        'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'I' => [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11],
        'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
        ':' => [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
        '-' => [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
        ' ' => [0x00; 7],
        _ => [0x1F, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1F],
    }
}
