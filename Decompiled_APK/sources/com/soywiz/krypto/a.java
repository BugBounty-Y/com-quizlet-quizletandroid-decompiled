package com.soywiz.krypto;

import android.R;
import com.google.android.gms.internal.mlkit_vision_barcode.H6;

/* loaded from: classes3.dex */
public final class a {
    public static final int[] g = new int[256];
    public static final int[] h = new int[256];
    public static final int[] i = new int[256];
    public static final int[] j = new int[256];
    public static final int[] k = new int[256];
    public static final int[] l = new int[256];
    public static final int[] m = new int[256];
    public static final int[] n = new int[256];
    public static final int[] o = new int[256];
    public static final int[] p = new int[256];
    public static final int[] q = {0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
    public final int[] a;
    public final int b;
    public final int c;
    public final int d;
    public final int[] e;
    public final int[] f;

    static {
        int i2 = 0;
        int[] iArr = new int[256];
        for (int i3 = 0; i3 < 256; i3++) {
            int i4 = i3 << 1;
            if (i3 >= 128) {
                i4 ^= 283;
            }
            iArr[i3] = i4;
        }
        int i5 = 0;
        while (true) {
            int i6 = i5;
            while (i2 < 256) {
                i2++;
                int i7 = ((((i5 << 1) ^ i5) ^ (i5 << 2)) ^ (i5 << 3)) ^ (i5 << 4);
                int i8 = ((i7 & 255) ^ (i7 >>> 8)) ^ 99;
                g[i6] = i8;
                h[i8] = i6;
                int i9 = iArr[i6];
                int i10 = iArr[i9];
                int i11 = iArr[i10];
                int i12 = (iArr[i8] * 257) ^ (i8 * R.attr.transcriptMode);
                i[i6] = (i12 << 24) | (i12 >>> 8);
                j[i6] = (i12 << 16) | (i12 >>> 16);
                k[i6] = (i12 << 8) | (i12 >>> 24);
                l[i6] = i12;
                int i13 = (((i10 * 65537) ^ (R.attr.cacheColorHint * i11)) ^ (i9 * 257)) ^ (R.attr.transcriptMode * i6);
                m[i8] = (i13 << 24) | (i13 >>> 8);
                n[i8] = (i13 << 16) | (i13 >>> 16);
                o[i8] = (i13 << 8) | (i13 >>> 24);
                p[i8] = i13;
                if (i6 == 0) {
                    break;
                }
                i6 = iArr[iArr[iArr[i11 ^ i9]]] ^ i9;
                i5 ^= iArr[iArr[i5]];
            }
            return;
            i5 = 1;
        }
    }

    public a(byte[] bArr) {
        int[] iArr;
        int i2;
        int[] iArrI = H6.i(bArr);
        this.a = iArrI;
        int length = iArrI.length;
        this.b = length;
        this.c = length + 6;
        int i3 = (length + 7) * 4;
        this.d = i3;
        int[] iArr2 = new int[i3];
        int i4 = 0;
        int i5 = 0;
        while (true) {
            iArr = g;
            if (i5 >= i3) {
                break;
            }
            int i6 = i5 + 1;
            int i7 = this.b;
            if (i5 < i7) {
                i2 = this.a[i5];
            } else {
                int i8 = iArr2[i5 - 1];
                int i9 = i5 % i7;
                if (i9 == 0) {
                    int i10 = (i8 >>> 24) | (i8 << 8);
                    i8 = (q[i5 / i7] << 24) ^ (iArr[i10 & 255] | (((iArr[(i10 >>> 24) & 255] << 24) | (iArr[(i10 >>> 16) & 255] << 16)) | (iArr[(i10 >>> 8) & 255] << 8)));
                } else if (i7 > 6 && i9 == 4) {
                    i8 = (iArr[(i8 >>> 24) & 255] << 24) | (iArr[(i8 >>> 16) & 255] << 16) | (iArr[(i8 >>> 8) & 255] << 8) | iArr[i8 & 255];
                }
                i2 = iArr2[i5 - i7] ^ i8;
            }
            iArr2[i5] = i2;
            i5 = i6;
        }
        this.e = iArr2;
        int i11 = this.d;
        int[] iArr3 = new int[i11];
        while (i4 < i11) {
            int i12 = i4 + 1;
            int i13 = this.d - i4;
            int i14 = i4 % 4 != 0 ? this.e[i13] : this.e[i13 - 4];
            if (i4 >= 4 && i13 > 4) {
                i14 = p[iArr[i14 & 255]] ^ ((m[iArr[(i14 >>> 24) & 255]] ^ n[iArr[(i14 >>> 16) & 255]]) ^ o[iArr[(i14 >>> 8) & 255]]);
            }
            iArr3[i4] = i14;
            i4 = i12;
        }
        this.f = iArr3;
    }

    public final void a(int[] iArr, int i2, int[] iArr2, int[] iArr3, int[] iArr4, int[] iArr5, int[] iArr6, int[] iArr7) {
        int i3 = iArr[i2] ^ iArr2[0];
        int i4 = i2 + 1;
        int i5 = 1;
        int i6 = iArr[i4] ^ iArr2[1];
        int i7 = i2 + 2;
        int i8 = iArr[i7] ^ iArr2[2];
        int i9 = i2 + 3;
        int i10 = iArr[i9] ^ iArr2[3];
        int i11 = 4;
        while (i5 < this.c) {
            i5++;
            int i12 = (((iArr3[(i3 >>> 24) & 255] ^ iArr4[(i6 >>> 16) & 255]) ^ iArr5[(i8 >>> 8) & 255]) ^ iArr6[i10 & 255]) ^ iArr2[i11];
            int i13 = iArr2[i11 + 1] ^ (((iArr3[(i6 >>> 24) & 255] ^ iArr4[(i8 >>> 16) & 255]) ^ iArr5[(i10 >>> 8) & 255]) ^ iArr6[i3 & 255]);
            int i14 = i11 + 3;
            int i15 = (((iArr3[(i8 >>> 24) & 255] ^ iArr4[(i10 >>> 16) & 255]) ^ iArr5[(i3 >>> 8) & 255]) ^ iArr6[i6 & 255]) ^ iArr2[i11 + 2];
            i11 += 4;
            i10 = (((iArr4[(i3 >>> 16) & 255] ^ iArr3[(i10 >>> 24) & 255]) ^ iArr5[(i6 >>> 8) & 255]) ^ iArr6[i8 & 255]) ^ iArr2[i14];
            i3 = i12;
            i6 = i13;
            i8 = i15;
        }
        int i16 = ((((iArr7[(i3 >>> 24) & 255] << 24) | (iArr7[(i6 >>> 16) & 255] << 16)) | (iArr7[(i8 >>> 8) & 255] << 8)) | iArr7[i10 & 255]) ^ iArr2[i11];
        int i17 = iArr2[i11 + 1] ^ ((((iArr7[(i6 >>> 24) & 255] << 24) | (iArr7[(i8 >>> 16) & 255] << 16)) | (iArr7[(i10 >>> 8) & 255] << 8)) | iArr7[i3 & 255]);
        int i18 = (iArr7[(i8 >>> 24) & 255] << 24) | (iArr7[(i10 >>> 16) & 255] << 16) | (iArr7[(i3 >>> 8) & 255] << 8) | iArr7[i6 & 255];
        int i19 = iArr2[i11 + 2] ^ i18;
        int i20 = ((((iArr7[(i3 >>> 16) & 255] << 16) | (iArr7[(i10 >>> 24) & 255] << 24)) | (iArr7[(i6 >>> 8) & 255] << 8)) | iArr7[i8 & 255]) ^ iArr2[i11 + 3];
        iArr[i2] = i16;
        iArr[i4] = i17;
        iArr[i7] = i19;
        iArr[i9] = i20;
    }
}
