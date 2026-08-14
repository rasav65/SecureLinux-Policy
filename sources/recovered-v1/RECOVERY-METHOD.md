# Glyph-ID text recovery v1

Purpose: recover a machine-searchable readable text representation for the two
pinned PDFs whose native ToUnicode/text layer is broken.

This is NOT OCR.

Algorithm:
1. Read glyph IDs and character origins with PyMuPDF `get_texttrace()`.
2. Build a glyph-ID -> Unicode reference map from the other eight readable
   pinned FSTEC PDFs.
3. Only accept a cross-document mapping when the same `(font family, glyph ID)`
   has one unambiguous Unicode character in the readable reference corpus.
4. Preserve ordinary low-GID Unicode supplied by the PDF toolchain.
5. Apply only three classes of explicit exceptions:
   - Times New Roman GID 178 -> em dash, visually verified in pinned
     `fstec-linux-2022.pdf`, page 2;
   - the six Calibri glyphs in the visually verified heading `Таблица 3`,
     pinned `fstec-vulnerability-analysis-2025.pdf`, page 21;
   - low-GID guillemets/en-dash are accepted only when the readable reference
     corpus confirms them unambiguously.
6. Reconstruct line order using `rawdict(sort=True)` and exact character-origin
   matching against `get_texttrace()`.
7. Require zero missing/colliding origin matches, zero U+FFFD, zero unresolved
   high glyphs, and deterministic double recovery.
8. Verify every previously blocked source-index locator exactly once.
9. Normalize recovered raw text with the exact archived `norm-v1` implementation.

The original PDFs, Step-2 extraction and source-v1 index remain immutable.
