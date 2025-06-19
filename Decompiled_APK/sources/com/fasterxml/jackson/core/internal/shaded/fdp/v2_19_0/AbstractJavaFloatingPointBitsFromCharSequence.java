package com.fasterxml.jackson.core.internal.shaded.fdp.v2_19_0;

/* loaded from: classes.dex */
abstract class AbstractJavaFloatingPointBitsFromCharSequence extends AbstractFloatValueParser {
    private long parseDecFloatLiteral(CharSequence charSequence, int i, int i2, int i3, boolean z, boolean z2) {
        char c;
        long j;
        int i4;
        int i5;
        int i6;
        int i7;
        long j2;
        boolean z3;
        int i8;
        AbstractJavaFloatingPointBitsFromCharSequence abstractJavaFloatingPointBitsFromCharSequence;
        int i9;
        boolean z4;
        int i10;
        long j3;
        char cCharAt;
        int i11 = -1;
        int i12 = i;
        long j4 = 0;
        char cCharAt2 = 0;
        boolean z5 = false;
        while (true) {
            c = '.';
            j = 10;
            if (i12 >= i3) {
                break;
            }
            cCharAt2 = charSequence.charAt(i12);
            char c2 = (char) (cCharAt2 - '0');
            if (c2 >= '\n') {
                if (cCharAt2 != '.') {
                    break;
                }
                z5 |= i11 >= 0;
                i11 = i12;
            } else {
                j4 = (j4 * 10) + c2;
            }
            i12++;
        }
        if (i11 < 0) {
            i4 = i12 - i;
            i11 = i12;
            i5 = 0;
        } else {
            i4 = (i12 - i) - 1;
            i5 = (i11 - i12) + 1;
        }
        if ((cCharAt2 | ' ') == 101) {
            i6 = i12 + 1;
            char cCharAt3 = AbstractNumberParser.charAt(charSequence, i6, i3);
            boolean z6 = cCharAt3 == '-';
            if (z6 || cCharAt3 == '+') {
                i6 = i12 + 2;
                cCharAt3 = AbstractNumberParser.charAt(charSequence, i6, i3);
            }
            char c3 = (char) (cCharAt3 - '0');
            boolean z7 = z5 | (c3 >= '\n');
            int i13 = 0;
            while (true) {
                if (i13 < 1024) {
                    i13 = (i13 * 10) + c3;
                }
                i6++;
                cCharAt = AbstractNumberParser.charAt(charSequence, i6, i3);
                char c4 = (char) (cCharAt - '0');
                if (c4 >= '\n') {
                    break;
                }
                c3 = c4;
            }
            if (z6) {
                i13 = -i13;
            }
            i5 += i13;
            int i14 = i13;
            cCharAt2 = cCharAt;
            i7 = i14;
            z5 = z7;
        } else {
            i6 = i12;
            i7 = 0;
        }
        if ((cCharAt2 | '\"') == 102) {
            i6++;
        }
        int iSkipWhitespace = skipWhitespace(charSequence, i6, i3);
        if (z5 || iSkipWhitespace < i3 || (!z2 && i4 == 0)) {
            throw new NumberFormatException("illegal syntax");
        }
        if (i4 > 19) {
            int i15 = i;
            int i16 = 0;
            long j5 = 0;
            while (i15 < i12) {
                char cCharAt4 = charSequence.charAt(i15);
                if (cCharAt4 != c) {
                    j3 = j;
                    if (Long.compareUnsigned(j5, 1000000000000000000L) >= 0) {
                        break;
                    }
                    j5 = ((j5 * j3) + cCharAt4) - 48;
                } else {
                    i16++;
                    j3 = j;
                }
                i15++;
                j = j3;
                c = '.';
            }
            i8 = (i11 - i15) + i16 + i7;
            j2 = j5;
            z3 = i15 < i12;
            abstractJavaFloatingPointBitsFromCharSequence = this;
            z4 = z;
            i10 = i5;
            i9 = i2;
        } else {
            j2 = j4;
            z3 = false;
            i8 = 0;
            abstractJavaFloatingPointBitsFromCharSequence = this;
            i9 = i2;
            z4 = z;
            i10 = i5;
        }
        return abstractJavaFloatingPointBitsFromCharSequence.valueOfFloatLiteral(charSequence, i9, i3, z4, j2, i10, z3, i8);
    }

    private long parseHexFloatLiteral(CharSequence charSequence, int i, int i2, int i3, boolean z) {
        char c;
        int i4;
        int iMin;
        char c2;
        int i5;
        int i6;
        int i7;
        long j;
        int i8;
        boolean z2;
        char cCharAt;
        int i9 = -1;
        int i10 = i;
        long j2 = 0;
        char cCharAt2 = 0;
        boolean z3 = false;
        while (true) {
            c = 4;
            if (i10 >= i3) {
                break;
            }
            cCharAt2 = charSequence.charAt(i10);
            int iLookupHex = AbstractNumberParser.lookupHex(cCharAt2);
            if (iLookupHex < 0) {
                if (iLookupHex != -4) {
                    break;
                }
                z3 |= i9 >= 0;
                int i11 = i10;
                while (i11 < i3 - 8) {
                    long jTryToParseEightHexDigits = FastDoubleSwar.tryToParseEightHexDigits(charSequence, i11 + 1);
                    if (jTryToParseEightHexDigits < 0) {
                        break;
                    }
                    j2 = (j2 << 32) + jTryToParseEightHexDigits;
                    i11 += 8;
                }
                int i12 = i10;
                i10 = i11;
                i9 = i12;
            } else {
                j2 = (j2 << 4) | iLookupHex;
            }
            i10++;
        }
        if (i9 < 0) {
            i4 = i10 - i;
            i9 = i10;
            iMin = 0;
        } else {
            i4 = (i10 - i) - 1;
            iMin = Math.min((i9 - i10) + 1, 1024) * 4;
        }
        boolean z4 = (cCharAt2 | ' ') == 112;
        if (z4) {
            i5 = i10 + 1;
            char cCharAt3 = AbstractNumberParser.charAt(charSequence, i5, i3);
            boolean z5 = cCharAt3 == '-';
            if (z5 || cCharAt3 == '+') {
                i5 = i10 + 2;
                cCharAt3 = AbstractNumberParser.charAt(charSequence, i5, i3);
            }
            char c3 = (char) (cCharAt3 - '0');
            boolean z6 = z3 | (c3 >= '\n');
            int i13 = 0;
            while (true) {
                if (i13 < 1024) {
                    i13 = (i13 * 10) + c3;
                }
                i5++;
                cCharAt = AbstractNumberParser.charAt(charSequence, i5, i3);
                c2 = c;
                char c4 = (char) (cCharAt - '0');
                if (c4 >= '\n') {
                    break;
                }
                c3 = c4;
                c = c2;
            }
            if (z5) {
                i13 = -i13;
            }
            iMin += i13;
            cCharAt2 = cCharAt;
            i6 = i13;
            z3 = z6;
        } else {
            c2 = 4;
            i5 = i10;
            i6 = 0;
        }
        if ((cCharAt2 | '\"') == 102) {
            i5++;
        }
        int iSkipWhitespace = skipWhitespace(charSequence, i5, i3);
        if (z3 || iSkipWhitespace < i3 || i4 == 0 || !z4) {
            throw new NumberFormatException("illegal syntax");
        }
        if (i4 > 16) {
            int i14 = i;
            int i15 = 0;
            long j3 = 0;
            while (i14 < i10) {
                int iLookupHex2 = AbstractNumberParser.lookupHex(charSequence.charAt(i14));
                if (iLookupHex2 < 0) {
                    i15++;
                } else {
                    if (Long.compareUnsigned(j3, 1000000000000000000L) >= 0) {
                        break;
                    }
                    j3 = (j3 << c2) | iLookupHex2;
                }
                i14++;
            }
            boolean z7 = i14 < i10;
            int i16 = i15;
            iSkipWhitespace = i14;
            i8 = i16;
            i7 = i6;
            j = j3;
            z2 = z7;
        } else {
            i7 = i6;
            j = j2;
            i8 = 0;
            z2 = false;
        }
        return valueOfHexLiteral(charSequence, i2, i3, z, j, iMin, z2, (((i9 - iSkipWhitespace) + i8) * 4) + i7);
    }

    private long parseNaNOrInfinity(CharSequence charSequence, int i, int i2, boolean z) {
        if (charSequence.charAt(i) == 'N') {
            int i3 = i + 2;
            if (i3 < i2 && charSequence.charAt(i + 1) == 'a' && charSequence.charAt(i3) == 'N' && skipWhitespace(charSequence, i + 3, i2) == i2) {
                return nan();
            }
        } else {
            int i4 = i + 7;
            if (i4 < i2 && charSequence.charAt(i) == 'I' && charSequence.charAt(i + 1) == 'n' && charSequence.charAt(i + 2) == 'f' && charSequence.charAt(i + 3) == 'i' && charSequence.charAt(i + 4) == 'n' && charSequence.charAt(i + 5) == 'i' && charSequence.charAt(i + 6) == 't' && charSequence.charAt(i4) == 'y' && skipWhitespace(charSequence, i + 8, i2) == i2) {
                return z ? negativeInfinity() : positiveInfinity();
            }
        }
        throw new NumberFormatException("illegal syntax");
    }

    private static int skipWhitespace(CharSequence charSequence, int i, int i2) {
        while (i < i2 && charSequence.charAt(i) <= ' ') {
            i++;
        }
        return i;
    }

    public abstract long nan();

    public abstract long negativeInfinity();

    public final long parseFloatingPointLiteral(CharSequence charSequence, int i, int i2) {
        int i3;
        int iCheckBounds = AbstractNumberParser.checkBounds(charSequence.length(), i, i2);
        int iSkipWhitespace = skipWhitespace(charSequence, i, iCheckBounds);
        if (iSkipWhitespace == iCheckBounds) {
            throw new NumberFormatException("illegal syntax");
        }
        char cCharAt = charSequence.charAt(iSkipWhitespace);
        boolean z = cCharAt == '-';
        if ((z || cCharAt == '+') && (cCharAt = AbstractNumberParser.charAt(charSequence, (iSkipWhitespace = iSkipWhitespace + 1), iCheckBounds)) == 0) {
            throw new NumberFormatException("illegal syntax");
        }
        if (cCharAt >= 'I') {
            return parseNaNOrInfinity(charSequence, iSkipWhitespace, iCheckBounds, z);
        }
        boolean z2 = cCharAt == '0';
        if (z2) {
            int i4 = iSkipWhitespace + 1;
            if ((AbstractNumberParser.charAt(charSequence, i4, iCheckBounds) | ' ') == 120) {
                return parseHexFloatLiteral(charSequence, iSkipWhitespace + 2, i, iCheckBounds, z);
            }
            i3 = i4;
        } else {
            i3 = iSkipWhitespace;
        }
        return parseDecFloatLiteral(charSequence, i3, i, iCheckBounds, z, z2);
    }

    public abstract long positiveInfinity();

    public abstract long valueOfFloatLiteral(CharSequence charSequence, int i, int i2, boolean z, long j, int i3, boolean z2, int i4);

    public abstract long valueOfHexLiteral(CharSequence charSequence, int i, int i2, boolean z, long j, int i3, boolean z2, int i4);
}
