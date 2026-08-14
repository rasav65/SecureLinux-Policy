## 5. Canonical primitives and bytes

### 5.1 IDs and hashes

ID/ref grammar:

```text
^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$
```

Reason code:

```text
^[A-Z][A-Z0-9_]{1,127}$
```

SHA-256 value:

```text
^[0-9a-f]{64}$
```

All input strings are valid Unicode scalar sequences, contain no unpaired
surrogate and are already NFC-normalized. Non-NFC input is rejected; it is not
silently normalized. Comparison and serialization therefore use the validated
string unchanged.

### 5.2 Canonical string and sequence order

String order: ascending Unicode scalar-value sequence after NFC.

Sequence-of-strings order:

1. compare elements pairwise by canonical string order;
2. first unequal element decides;
3. an exact shorter prefix sorts first;
4. same length and equal elements means equal sequence.

This is the exact order for `node_path`.

### 5.3 Typed literals and paths

Allowed variants exactly: string, signed-64 integer, boolean, path, identifier,
non-empty string-set and non-empty integer-set.

Signed integer domain is exactly:

```text
minimum = -9223372036854775808
maximum =  9223372036854775807
```

Parsing and validation MUST preserve the integer token exactly or use an
arbitrary-precision integer before the bounds check. IEEE-754 conversion before
validation is forbidden.

Built-in schema mapping is exact:

| Literal `kind` | Literal schema ID | Element schema ID |
|---|---|---|
| string | `selector-value/string/v1` | same |
| integer | `selector-value/signed-int64/v1` | same |
| boolean | `selector-value/boolean/v1` | same |
| path | `selector-value/absolute-lexical-path/v1` | same |
| identifier | `selector-value/identifier/v1` | same |
| string-set | `selector-value/string-set/v1` | `selector-value/string/v1` |
| integer-set | `selector-value/signed-int64-set/v1` | `selector-value/signed-int64/v1` |

No other schema ID describes these variants. Set values are unique and
canonically ordered.

An absolute lexical POSIX path begins with `/`, contains no NUL or empty
interior segment, and contains no segment exactly `.` or `..`, including the
first and final segment. Therefore `/.`, `/..`, `/./x`, `/../x`, `/a/.` and
`/a/..` are invalid. No filesystem canonicalization, symlink resolution, case
folding or environment expansion is performed.

### 5.4 Canonical JSON bytes

The only byte serialization used for hashes, semantic duplicate identity and
raw-candidate evidence ordering is:

1. validate the typed object first;
2. verify every string is already NFC and serialize it unchanged;
3. allow only `null`, boolean, signed-64 integer, string, array and object;
4. serialize integers as base-10 with no leading zero and `-0` forbidden;
5. sort object keys by section 5.2 string order;
6. emit no insignificant whitespace;
7. escape quotation mark and reverse solidus; use `\b`, `\f`, `\n`, `\r`,
   `\t` for those controls and lowercase `\u00xx` for remaining U+0000-U+001F;
8. do not escape other Unicode scalar values;
9. encode the resulting JSON text as UTF-8 without BOM.

Floats, NaN, infinities, non-string object keys and implementation insertion
order are forbidden. Alternative escapes such as `\/` or `\uXXXX` for
otherwise unescaped printable scalars are forbidden. Byte-array comparison
examines unsigned bytes from left to right; the first unequal byte decides and
an exact shorter prefix sorts first.

```text
canonical_digest_sha256 = SHA256(exact canonical JSON bytes)
```

### 5.5 Canonical array orders

```text
unit arrays              -> section 14 unit order
reason_codes             -> unique canonical-string order
provenance_refs          -> unique canonical-string order
resolver slots/bindings  -> slot_ref order
source entries           -> entry_ref order
source decisions         -> entry_ref order
filters                  -> filter_ref order
union members            -> node_ref order
identity_values          -> identity.fields order
filter_facts             -> field_ref order
ordering_values          -> declared non-identity ordering-field order
raw evidence             -> unsigned lexicographic canonical-byte order
final targets            -> declared selector total order
```

No traversal or hash-map iteration order is observable.

