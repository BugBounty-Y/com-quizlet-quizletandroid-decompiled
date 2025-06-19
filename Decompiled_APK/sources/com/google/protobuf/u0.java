package com.google.protobuf;

import com.amazon.device.ads.DtbConstants;

/* loaded from: classes2.dex */
public final class u0 extends h0 {
    public final /* synthetic */ int c;

    public static int g(long j, byte[] bArr, int i, int i2) {
        if (i2 == 0) {
            h0 h0Var = w0.a;
            if (i > -12) {
                return -1;
            }
            return i;
        }
        if (i2 == 1) {
            return w0.c(i, t0.g(bArr, j));
        }
        if (i2 == 2) {
            return w0.d(i, t0.g(bArr, j), t0.g(bArr, j + 1));
        }
        throw new AssertionError();
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x004a  */
    @Override // com.google.protobuf.h0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String a(int r11, byte[] r12, int r13) throws com.google.protobuf.InvalidProtocolBufferException {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.u0.a(int, byte[], int):java.lang.String");
    }

    @Override // com.google.protobuf.h0
    public final int b(String str, byte[] bArr, int i, int i2) {
        int i3;
        int i4;
        char cCharAt;
        long j;
        char c;
        long j2;
        long j3;
        char c2;
        int i5;
        char cCharAt2;
        switch (this.c) {
            case 0:
                int length = str.length();
                int i6 = i2 + i;
                int i7 = 0;
                while (i7 < length && (i4 = i7 + i) < i6 && (cCharAt = str.charAt(i7)) < 128) {
                    bArr[i4] = (byte) cCharAt;
                    i7++;
                }
                if (i7 == length) {
                    return i + length;
                }
                int i8 = i + i7;
                while (i7 < length) {
                    char cCharAt3 = str.charAt(i7);
                    if (cCharAt3 < 128 && i8 < i6) {
                        bArr[i8] = (byte) cCharAt3;
                        i8++;
                    } else if (cCharAt3 < 2048 && i8 <= i6 - 2) {
                        int i9 = i8 + 1;
                        bArr[i8] = (byte) ((cCharAt3 >>> 6) | 960);
                        i8 += 2;
                        bArr[i9] = (byte) ((cCharAt3 & '?') | 128);
                    } else {
                        if ((cCharAt3 >= 55296 && 57343 >= cCharAt3) || i8 > i6 - 3) {
                            if (i8 > i6 - 4) {
                                if (55296 <= cCharAt3 && cCharAt3 <= 57343 && ((i3 = i7 + 1) == str.length() || !Character.isSurrogatePair(cCharAt3, str.charAt(i3)))) {
                                    throw new v0(i7, length);
                                }
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + cCharAt3 + " at index " + i8);
                            }
                            int i10 = i7 + 1;
                            if (i10 != str.length()) {
                                char cCharAt4 = str.charAt(i10);
                                if (Character.isSurrogatePair(cCharAt3, cCharAt4)) {
                                    int codePoint = Character.toCodePoint(cCharAt3, cCharAt4);
                                    bArr[i8] = (byte) ((codePoint >>> 18) | 240);
                                    bArr[i8 + 1] = (byte) (((codePoint >>> 12) & 63) | 128);
                                    int i11 = i8 + 3;
                                    bArr[i8 + 2] = (byte) (((codePoint >>> 6) & 63) | 128);
                                    i8 += 4;
                                    bArr[i11] = (byte) ((codePoint & 63) | 128);
                                    i7 = i10;
                                } else {
                                    i7 = i10;
                                }
                            }
                            throw new v0(i7 - 1, length);
                        }
                        bArr[i8] = (byte) ((cCharAt3 >>> '\f') | DtbConstants.DEFAULT_PLAYER_HEIGHT);
                        int i12 = i8 + 2;
                        bArr[i8 + 1] = (byte) (((cCharAt3 >>> 6) & 63) | 128);
                        i8 += 3;
                        bArr[i12] = (byte) ((cCharAt3 & '?') | 128);
                    }
                    i7++;
                }
                return i8;
            default:
                long j4 = i;
                long j5 = i2 + j4;
                int length2 = str.length();
                if (length2 > i2 || bArr.length - i2 < i) {
                    throw new ArrayIndexOutOfBoundsException("Failed writing " + str.charAt(length2 - 1) + " at index " + (i + i2));
                }
                int i13 = 0;
                while (true) {
                    j = 1;
                    c = 128;
                    if (i13 < length2 && (cCharAt2 = str.charAt(i13)) < 128) {
                        t0.k(bArr, (byte) cCharAt2, j4);
                        i13++;
                        j4 = 1 + j4;
                    }
                }
                if (i13 == length2) {
                    return (int) j4;
                }
                while (i13 < length2) {
                    char cCharAt5 = str.charAt(i13);
                    if (cCharAt5 < c && j4 < j5) {
                        t0.k(bArr, (byte) cCharAt5, j4);
                        c2 = c;
                        j2 = j;
                        j3 = j4 + j;
                    } else if (cCharAt5 >= 2048 || j4 > j5 - 2) {
                        j2 = j;
                        if ((cCharAt5 >= 55296 && 57343 >= cCharAt5) || j4 > j5 - 3) {
                            long j6 = j4;
                            if (j6 > j5 - 4) {
                                if (55296 <= cCharAt5 && cCharAt5 <= 57343 && ((i5 = i13 + 1) == length2 || !Character.isSurrogatePair(cCharAt5, str.charAt(i5)))) {
                                    throw new v0(i13, length2);
                                }
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + cCharAt5 + " at index " + j6);
                            }
                            int i14 = i13 + 1;
                            if (i14 != length2) {
                                char cCharAt6 = str.charAt(i14);
                                if (Character.isSurrogatePair(cCharAt5, cCharAt6)) {
                                    int codePoint2 = Character.toCodePoint(cCharAt5, cCharAt6);
                                    t0.k(bArr, (byte) ((codePoint2 >>> 18) | 240), j6);
                                    c2 = 128;
                                    t0.k(bArr, (byte) (((codePoint2 >>> 12) & 63) | 128), j6 + j2);
                                    t0.k(bArr, (byte) (((codePoint2 >>> 6) & 63) | 128), j6 + 2);
                                    t0.k(bArr, (byte) ((codePoint2 & 63) | 128), j6 + 3);
                                    j3 = j6 + 4;
                                    i13 = i14;
                                } else {
                                    i13 = i14;
                                }
                            }
                            throw new v0(i13 - 1, length2);
                        }
                        t0.k(bArr, (byte) ((cCharAt5 >>> '\f') | DtbConstants.DEFAULT_PLAYER_HEIGHT), j4);
                        long j7 = j4;
                        t0.k(bArr, (byte) (((cCharAt5 >>> 6) & 63) | 128), j4 + j2);
                        j3 = j7 + 3;
                        t0.k(bArr, (byte) ((cCharAt5 & '?') | 128), j7 + 2);
                        c2 = 128;
                    } else {
                        j2 = j;
                        t0.k(bArr, (byte) ((cCharAt5 >>> 6) | 960), j4);
                        t0.k(bArr, (byte) ((cCharAt5 & '?') | c), j4 + j2);
                        j3 = j4 + 2;
                        c2 = c;
                    }
                    i13++;
                    c = c2;
                    j4 = j3;
                    j = j2;
                }
                return (int) j4;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:75:0x00fa, code lost:
    
        return -1;
     */
    @Override // com.google.protobuf.h0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int e(int r18, byte[] r19, int r20) {
        /*
            Method dump skipped, instructions count: 410
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.u0.e(int, byte[], int):int");
    }
}
