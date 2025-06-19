package androidx.datastore.preferences.protobuf;

import com.amazon.device.ads.DtbConstants;

/* loaded from: classes.dex */
public final class h0 {
    public static final /* synthetic */ int b = 0;
    public final /* synthetic */ int a;

    public /* synthetic */ h0(int i) {
        this.a = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(io.ktor.client.statement.b r5, java.nio.charset.Charset r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof io.ktor.client.statement.d
            if (r0 == 0) goto L13
            r0 = r7
            io.ktor.client.statement.d r0 = (io.ktor.client.statement.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            io.ktor.client.statement.d r0 = new io.ktor.client.statement.d
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.nio.charset.CharsetDecoder r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L61
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.nio.charset.Charset r7 = com.google.android.gms.internal.mlkit_vision_barcode.Z6.b(r5)
            if (r7 != 0) goto L3b
            goto L3c
        L3b:
            r6 = r7
        L3c:
            java.nio.charset.CharsetDecoder r6 = r6.newDecoder()
            io.ktor.client.call.b r5 = r5.b()
            java.lang.Class<kotlinx.io.i> r7 = kotlinx.io.i.class
            kotlin.jvm.internal.i r2 = kotlin.jvm.internal.K.a(r7)
            kotlin.jvm.internal.U r7 = kotlin.jvm.internal.K.c(r7)     // Catch: java.lang.Throwable -> L4f
            goto L50
        L4f:
            r7 = 0
        L50:
            io.ktor.util.reflect.a r4 = new io.ktor.util.reflect.a
            r4.<init>(r2, r7)
            r0.j = r6
            r0.l = r3
            java.lang.Object r7 = r5.a(r4, r0)
            if (r7 != r1) goto L60
            return r1
        L60:
            r5 = r6
        L61:
            if (r7 == 0) goto L6d
            kotlinx.io.i r7 = (kotlinx.io.i) r7
            kotlin.jvm.internal.Intrinsics.d(r5)
            java.lang.String r5 = com.google.android.gms.internal.mlkit_vision_barcode.t7.d(r5, r7)
            return r5
        L6d:
            java.lang.NullPointerException r5 = new java.lang.NullPointerException
            java.lang.String r6 = "null cannot be cast to non-null type kotlinx.io.Source"
            r5.<init>(r6)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.h0.a(io.ktor.client.statement.b, java.nio.charset.Charset, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String b(int r11, byte[] r12, int r13) {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.protobuf.h0.b(int, byte[], int):java.lang.String");
    }

    public final int c(String str, byte[] bArr, int i, int i2) {
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
        switch (this.a) {
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
                                    throw new i0(i7, length);
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
                            throw new i0(i7 - 1, length);
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
                        g0.j(bArr, (byte) cCharAt2, j4);
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
                        g0.j(bArr, (byte) cCharAt5, j4);
                        c2 = c;
                        j2 = j;
                        j3 = j4 + j;
                    } else if (cCharAt5 >= 2048 || j4 > j5 - 2) {
                        j2 = j;
                        if ((cCharAt5 >= 55296 && 57343 >= cCharAt5) || j4 > j5 - 3) {
                            long j6 = j4;
                            if (j6 > j5 - 4) {
                                if (55296 <= cCharAt5 && cCharAt5 <= 57343 && ((i5 = i13 + 1) == length2 || !Character.isSurrogatePair(cCharAt5, str.charAt(i5)))) {
                                    throw new i0(i13, length2);
                                }
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + cCharAt5 + " at index " + j6);
                            }
                            int i14 = i13 + 1;
                            if (i14 != length2) {
                                char cCharAt6 = str.charAt(i14);
                                if (Character.isSurrogatePair(cCharAt5, cCharAt6)) {
                                    int codePoint2 = Character.toCodePoint(cCharAt5, cCharAt6);
                                    g0.j(bArr, (byte) ((codePoint2 >>> 18) | 240), j6);
                                    c2 = 128;
                                    g0.j(bArr, (byte) (((codePoint2 >>> 12) & 63) | 128), j6 + j2);
                                    g0.j(bArr, (byte) (((codePoint2 >>> 6) & 63) | 128), j6 + 2);
                                    g0.j(bArr, (byte) ((codePoint2 & 63) | 128), j6 + 3);
                                    j3 = j6 + 4;
                                    i13 = i14;
                                } else {
                                    i13 = i14;
                                }
                            }
                            throw new i0(i13 - 1, length2);
                        }
                        g0.j(bArr, (byte) ((cCharAt5 >>> '\f') | DtbConstants.DEFAULT_PLAYER_HEIGHT), j4);
                        long j7 = j4;
                        g0.j(bArr, (byte) (((cCharAt5 >>> 6) & 63) | 128), j4 + j2);
                        j3 = j7 + 3;
                        g0.j(bArr, (byte) ((cCharAt5 & '?') | 128), j7 + 2);
                        c2 = 128;
                    } else {
                        j2 = j;
                        g0.j(bArr, (byte) ((cCharAt5 >>> 6) | 960), j4);
                        g0.j(bArr, (byte) ((cCharAt5 & '?') | c), j4 + j2);
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
}
