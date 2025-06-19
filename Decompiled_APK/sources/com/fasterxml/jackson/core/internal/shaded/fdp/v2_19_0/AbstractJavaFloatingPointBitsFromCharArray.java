package com.fasterxml.jackson.core.internal.shaded.fdp.v2_19_0;

/* loaded from: classes.dex */
abstract class AbstractJavaFloatingPointBitsFromCharArray extends AbstractFloatValueParser {
    private long parseDecFloatLiteral(char[] cArr, int i, int i2, int i3, boolean z, boolean z2) {
        char c;
        long j;
        int i4;
        int i5;
        int i6;
        int i7;
        long j2;
        boolean z3;
        int i8;
        long j3;
        char cCharAt;
        int iMin = Math.min(i3 - 4, 1073741824);
        int i9 = -1;
        int i10 = i;
        long j4 = 0;
        char c2 = 0;
        boolean z4 = false;
        while (true) {
            c = '.';
            j = 10;
            if (i10 >= i3) {
                break;
            }
            c2 = cArr[i10];
            char c3 = (char) (c2 - '0');
            if (c3 >= '\n') {
                if (c2 != '.') {
                    break;
                }
                z4 |= i9 >= 0;
                int i11 = i10;
                while (i11 < iMin) {
                    int iTryToParseFourDigits = FastDoubleSwar.tryToParseFourDigits(cArr, i11 + 1);
                    if (iTryToParseFourDigits < 0) {
                        break;
                    }
                    j4 = (j4 * 10000) + iTryToParseFourDigits;
                    i11 += 4;
                }
                int i12 = i10;
                i10 = i11;
                i9 = i12;
            } else {
                j4 = (j4 * 10) + c3;
            }
            i10++;
        }
        if (i9 < 0) {
            i4 = i10 - i;
            i9 = i10;
            i5 = 0;
        } else {
            i4 = (i10 - i) - 1;
            i5 = (i9 - i10) + 1;
        }
        if ((c2 | ' ') == 101) {
            i6 = i10 + 1;
            char cCharAt2 = AbstractNumberParser.charAt(cArr, i6, i3);
            boolean z5 = cCharAt2 == '-';
            if (z5 || cCharAt2 == '+') {
                i6 = i10 + 2;
                cCharAt2 = AbstractNumberParser.charAt(cArr, i6, i3);
            }
            char c4 = (char) (cCharAt2 - '0');
            boolean z6 = z4 | (c4 >= '\n');
            int i13 = 0;
            while (true) {
                if (i13 < 1024) {
                    i13 = (i13 * 10) + c4;
                }
                i6++;
                cCharAt = AbstractNumberParser.charAt(cArr, i6, i3);
                char c5 = (char) (cCharAt - '0');
                if (c5 >= '\n') {
                    break;
                }
                c4 = c5;
            }
            if (z5) {
                i13 = -i13;
            }
            i5 += i13;
            int i14 = i13;
            c2 = cCharAt;
            i7 = i14;
            z4 = z6;
        } else {
            i6 = i10;
            i7 = 0;
        }
        if ((c2 | '\"') == 102) {
            i6++;
        }
        int iSkipWhitespace = skipWhitespace(cArr, i6, i3);
        if (z4 || iSkipWhitespace < i3 || (!z2 && i4 == 0)) {
            throw new NumberFormatException("illegal syntax");
        }
        if (i4 > 19) {
            int i15 = i;
            int i16 = 0;
            long j5 = 0;
            while (i15 < i10) {
                char c6 = cArr[i15];
                if (c6 != c) {
                    j3 = j;
                    if (Long.compareUnsigned(j5, 1000000000000000000L) >= 0) {
                        break;
                    }
                    j5 = ((j5 * j3) + c6) - 48;
                } else {
                    i16++;
                    j3 = j;
                }
                i15++;
                j = j3;
                c = '.';
            }
            i8 = i7 + (i9 - i15) + i16;
            j2 = j5;
            z3 = i15 < i10;
        } else {
            j2 = j4;
            z3 = false;
            i8 = 0;
        }
        return valueOfFloatLiteral(cArr, i2, i3, z, j2, i5, z3, i8);
    }

    private long parseHexFloatLiteral(char[] cArr, int i, int i2, int i3, boolean z) {
        int i4;
        int iMin;
        char c;
        boolean z2;
        int i5;
        int i6;
        long j;
        boolean z3;
        int i7;
        int i8 = -1;
        int i9 = i;
        long j2 = 0;
        char cCharAt = 0;
        boolean z4 = false;
        while (i9 < i3) {
            cCharAt = cArr[i9];
            int iLookupHex = AbstractNumberParser.lookupHex(cCharAt);
            if (iLookupHex < 0) {
                if (iLookupHex != -4) {
                    break;
                }
                z4 |= i8 >= 0;
                int i10 = i9;
                while (i10 < i3 - 8) {
                    long jTryToParseEightHexDigits = tryToParseEightHexDigits(cArr, i10 + 1);
                    if (jTryToParseEightHexDigits < 0) {
                        break;
                    }
                    j2 = (j2 << 32) + jTryToParseEightHexDigits;
                    i10 += 8;
                }
                int i11 = i9;
                i9 = i10;
                i8 = i11;
            } else {
                j2 = (j2 << 4) | iLookupHex;
            }
            i9++;
        }
        int i12 = 1024;
        if (i8 < 0) {
            i4 = i9 - i;
            i8 = i9;
            iMin = 0;
        } else {
            i4 = (i9 - i) - 1;
            iMin = Math.min((i8 - i9) + 1, 1024) * 4;
        }
        boolean z5 = (cCharAt | ' ') == 112;
        if (z5) {
            i5 = i9 + 1;
            char cCharAt2 = AbstractNumberParser.charAt(cArr, i5, i3);
            c = 4;
            boolean z6 = cCharAt2 == '-';
            z2 = true;
            if (z6 || cCharAt2 == '+') {
                i5 = i9 + 2;
                cCharAt2 = AbstractNumberParser.charAt(cArr, i5, i3);
            }
            char c2 = (char) (cCharAt2 - '0');
            boolean z7 = z4 | (c2 >= '\n');
            int i13 = 0;
            while (true) {
                if (i13 < i12) {
                    i13 = (i13 * 10) + c2;
                }
                i5++;
                cCharAt = AbstractNumberParser.charAt(cArr, i5, i3);
                char c3 = (char) (cCharAt - '0');
                if (c3 >= '\n') {
                    break;
                }
                c2 = c3;
                i12 = 1024;
            }
            if (z6) {
                i13 = -i13;
            }
            iMin += i13;
            i6 = i13;
            z4 = z7;
        } else {
            c = 4;
            z2 = true;
            i5 = i9;
            i6 = 0;
        }
        if ((cCharAt | '\"') == 102) {
            i5++;
        }
        int iSkipWhitespace = skipWhitespace(cArr, i5, i3);
        if (z4 || iSkipWhitespace < i3 || i4 == 0 || !z5) {
            throw new NumberFormatException("illegal syntax");
        }
        if (i4 > 16) {
            int i14 = i;
            int i15 = 0;
            long j3 = 0;
            while (i14 < i9) {
                int iLookupHex2 = AbstractNumberParser.lookupHex(cArr[i14]);
                if (iLookupHex2 < 0) {
                    i15++;
                } else {
                    if (Long.compareUnsigned(j3, 1000000000000000000L) >= 0) {
                        break;
                    }
                    j3 = (j3 << c) | iLookupHex2;
                }
                i14++;
            }
            boolean z8 = i14 < i9 ? z2 : false;
            j = j3;
            z3 = z8;
            i7 = i15;
            iSkipWhitespace = i14;
        } else {
            j = j2;
            z3 = false;
            i7 = 0;
        }
        return valueOfHexLiteral(cArr, i2, i3, z, j, iMin, z3, (((i8 - iSkipWhitespace) + i7) * 4) + i6);
    }

    private long parseNaNOrInfinity(char[] cArr, int i, int i2, boolean z) {
        char c = cArr[i];
        if (c == 'N') {
            int i3 = i + 2;
            if (i3 < i2 && cArr[i + 1] == 'a' && cArr[i3] == 'N' && skipWhitespace(cArr, i + 3, i2) == i2) {
                return nan();
            }
        } else {
            int i4 = i + 7;
            if (i4 < i2 && c == 'I' && cArr[i + 1] == 'n' && cArr[i + 2] == 'f' && cArr[i + 3] == 'i' && cArr[i + 4] == 'n' && cArr[i + 5] == 'i' && cArr[i + 6] == 't' && cArr[i4] == 'y' && skipWhitespace(cArr, i + 8, i2) == i2) {
                return z ? negativeInfinity() : positiveInfinity();
            }
        }
        throw new NumberFormatException("illegal syntax");
    }

    private static int skipWhitespace(char[] cArr, int i, int i2) {
        while (i < i2 && cArr[i] <= ' ') {
            i++;
        }
        return i;
    }

    private long tryToParseEightHexDigits(char[] cArr, int i) {
        return FastDoubleSwar.tryToParseEightHexDigits(cArr, i);
    }

    public abstract long nan();

    public abstract long negativeInfinity();

    public long parseFloatingPointLiteral(char[] cArr, int i, int i2) {
        int i3;
        int iCheckBounds = AbstractNumberParser.checkBounds(cArr.length, i, i2);
        int iSkipWhitespace = skipWhitespace(cArr, i, iCheckBounds);
        if (iSkipWhitespace == iCheckBounds) {
            throw new NumberFormatException("illegal syntax");
        }
        char cCharAt = cArr[iSkipWhitespace];
        boolean z = cCharAt == '-';
        if ((z || cCharAt == '+') && (cCharAt = AbstractNumberParser.charAt(cArr, (iSkipWhitespace = iSkipWhitespace + 1), iCheckBounds)) == 0) {
            throw new NumberFormatException("illegal syntax");
        }
        if (cCharAt >= 'I') {
            return parseNaNOrInfinity(cArr, iSkipWhitespace, iCheckBounds, z);
        }
        boolean z2 = cCharAt == '0';
        if (z2) {
            int i4 = iSkipWhitespace + 1;
            if ((AbstractNumberParser.charAt(cArr, i4, iCheckBounds) | ' ') == 120) {
                return parseHexFloatLiteral(cArr, iSkipWhitespace + 2, i, iCheckBounds, z);
            }
            i3 = i4;
        } else {
            i3 = iSkipWhitespace;
        }
        return parseDecFloatLiteral(cArr, i3, i, iCheckBounds, z, z2);
    }

    public abstract long positiveInfinity();

    public abstract long valueOfFloatLiteral(char[] cArr, int i, int i2, boolean z, long j, int i3, boolean z2, int i4);

    public abstract long valueOfHexLiteral(char[] cArr, int i, int i2, boolean z, long j, int i3, boolean z2, int i4);
}
