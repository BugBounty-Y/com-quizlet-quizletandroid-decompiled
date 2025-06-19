package com.google.android.gms.internal.mlkit_vision_common;

import com.google.android.gms.internal.ads.C2776wA;
import com.google.android.gms.internal.measurement.C3035o2;
import com.google.android.gms.internal.measurement.C3079x2;
import com.google.android.gms.internal.measurement.InterfaceC2975c2;
import com.google.android.gms.internal.measurement.InterfaceC3069v2;
import com.google.android.gms.internal.measurement.zzmm;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.y3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3566y3 {
    public static final /* synthetic */ int a = 0;

    public static int a(byte[] bArr, int i, C2776wA c2776wA) {
        int iF = f(bArr, i, c2776wA);
        int i2 = c2776wA.a;
        if (i2 < 0) {
            throw new zzmm("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        if (i2 > bArr.length - iF) {
            throw new zzmm("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        if (i2 == 0) {
            c2776wA.c = com.google.android.gms.internal.measurement.O1.c;
            return iF;
        }
        c2776wA.c = com.google.android.gms.internal.measurement.O1.g(iF, bArr, i2);
        return iF + i2;
    }

    public static int b(int i, byte[] bArr) {
        int i2 = bArr[i] & 255;
        int i3 = bArr[i + 1] & 255;
        int i4 = bArr[i + 2] & 255;
        return ((bArr[i + 3] & 255) << 24) | (i3 << 8) | i2 | (i4 << 16);
    }

    public static int c(InterfaceC3069v2 interfaceC3069v2, int i, byte[] bArr, int i2, int i3, InterfaceC2975c2 interfaceC2975c2, C2776wA c2776wA) {
        com.google.android.gms.internal.measurement.W1 w1Zze = interfaceC3069v2.zze();
        InterfaceC3069v2 interfaceC3069v22 = interfaceC3069v2;
        byte[] bArr2 = bArr;
        int i4 = i3;
        C2776wA c2776wA2 = c2776wA;
        int iK = k(w1Zze, interfaceC3069v22, bArr2, i2, i4, c2776wA2);
        interfaceC3069v22.a(w1Zze);
        c2776wA2.c = w1Zze;
        interfaceC2975c2.add(w1Zze);
        while (iK < i4) {
            C2776wA c2776wA3 = c2776wA2;
            int i5 = i4;
            int iF = f(bArr2, iK, c2776wA3);
            if (i != c2776wA3.a) {
                break;
            }
            byte[] bArr3 = bArr2;
            InterfaceC3069v2 interfaceC3069v23 = interfaceC3069v22;
            com.google.android.gms.internal.measurement.W1 w1Zze2 = interfaceC3069v23.zze();
            iK = k(w1Zze2, interfaceC3069v23, bArr3, iF, i5, c2776wA3);
            interfaceC3069v22 = interfaceC3069v23;
            bArr2 = bArr3;
            i4 = i5;
            c2776wA2 = c2776wA3;
            interfaceC3069v22.a(w1Zze2);
            c2776wA2.c = w1Zze2;
            interfaceC2975c2.add(w1Zze2);
        }
        return iK;
    }

    public static int d(byte[] bArr, int i, InterfaceC2975c2 interfaceC2975c2, C2776wA c2776wA) {
        com.google.android.gms.internal.measurement.X1 x1 = (com.google.android.gms.internal.measurement.X1) interfaceC2975c2;
        int iF = f(bArr, i, c2776wA);
        int i2 = c2776wA.a + iF;
        while (iF < i2) {
            iF = f(bArr, iF, c2776wA);
            x1.e(c2776wA.a);
        }
        if (iF == i2) {
            return iF;
        }
        throw new zzmm("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    public static int e(int i, byte[] bArr, int i2, int i3, C3079x2 c3079x2, C2776wA c2776wA) {
        if ((i >>> 3) == 0) {
            throw new zzmm("Protocol message contained an invalid tag (zero).");
        }
        int i4 = i & 7;
        if (i4 == 0) {
            int i5 = i(bArr, i2, c2776wA);
            c3079x2.c(i, Long.valueOf(c2776wA.b));
            return i5;
        }
        if (i4 == 1) {
            c3079x2.c(i, Long.valueOf(l(i2, bArr)));
            return i2 + 8;
        }
        if (i4 == 2) {
            int iF = f(bArr, i2, c2776wA);
            int i6 = c2776wA.a;
            if (i6 < 0) {
                throw new zzmm("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
            }
            if (i6 > bArr.length - iF) {
                throw new zzmm("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
            if (i6 == 0) {
                c3079x2.c(i, com.google.android.gms.internal.measurement.O1.c);
            } else {
                c3079x2.c(i, com.google.android.gms.internal.measurement.O1.g(iF, bArr, i6));
            }
            return iF + i6;
        }
        if (i4 != 3) {
            if (i4 != 5) {
                throw new zzmm("Protocol message contained an invalid tag (zero).");
            }
            c3079x2.c(i, Integer.valueOf(b(i2, bArr)));
            return i2 + 4;
        }
        int i7 = (i & (-8)) | 4;
        C3079x2 c3079x2B = C3079x2.b();
        int i8 = c2776wA.d + 1;
        c2776wA.d = i8;
        if (i8 >= 100) {
            throw new zzmm("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i9 = 0;
        while (true) {
            if (i2 >= i3) {
                break;
            }
            int iF2 = f(bArr, i2, c2776wA);
            int i10 = c2776wA.a;
            if (i10 == i7) {
                i9 = i10;
                i2 = iF2;
                break;
            }
            i2 = e(i10, bArr, iF2, i3, c3079x2B, c2776wA);
            i9 = i10;
        }
        c2776wA.d--;
        if (i2 > i3 || i9 != i7) {
            throw new zzmm("Failed to parse the message.");
        }
        c3079x2.c(i, c3079x2B);
        return i2;
    }

    public static int f(byte[] bArr, int i, C2776wA c2776wA) {
        int i2 = i + 1;
        byte b = bArr[i];
        if (b < 0) {
            return g(b, bArr, i2, c2776wA);
        }
        c2776wA.a = b;
        return i2;
    }

    public static int g(int i, byte[] bArr, int i2, C2776wA c2776wA) {
        byte b = bArr[i2];
        int i3 = i2 + 1;
        int i4 = i & 127;
        if (b >= 0) {
            c2776wA.a = i4 | (b << 7);
            return i3;
        }
        int i5 = i4 | ((b & Byte.MAX_VALUE) << 7);
        int i6 = i2 + 2;
        byte b2 = bArr[i3];
        if (b2 >= 0) {
            c2776wA.a = i5 | (b2 << 14);
            return i6;
        }
        int i7 = i5 | ((b2 & Byte.MAX_VALUE) << 14);
        int i8 = i2 + 3;
        byte b3 = bArr[i6];
        if (b3 >= 0) {
            c2776wA.a = i7 | (b3 << 21);
            return i8;
        }
        int i9 = i7 | ((b3 & Byte.MAX_VALUE) << 21);
        int i10 = i2 + 4;
        byte b4 = bArr[i8];
        if (b4 >= 0) {
            c2776wA.a = i9 | (b4 << 28);
            return i10;
        }
        int i11 = i9 | ((b4 & Byte.MAX_VALUE) << 28);
        while (true) {
            int i12 = i10 + 1;
            if (bArr[i10] >= 0) {
                c2776wA.a = i11;
                return i12;
            }
            i10 = i12;
        }
    }

    public static int h(int i, byte[] bArr, int i2, int i3, InterfaceC2975c2 interfaceC2975c2, C2776wA c2776wA) {
        com.google.android.gms.internal.measurement.X1 x1 = (com.google.android.gms.internal.measurement.X1) interfaceC2975c2;
        int iF = f(bArr, i2, c2776wA);
        x1.e(c2776wA.a);
        while (iF < i3) {
            int iF2 = f(bArr, iF, c2776wA);
            if (i != c2776wA.a) {
                break;
            }
            iF = f(bArr, iF2, c2776wA);
            x1.e(c2776wA.a);
        }
        return iF;
    }

    public static int i(byte[] bArr, int i, C2776wA c2776wA) {
        long j = bArr[i];
        int i2 = i + 1;
        if (j >= 0) {
            c2776wA.b = j;
            return i2;
        }
        int i3 = i + 2;
        byte b = bArr[i2];
        long j2 = (j & 127) | ((b & Byte.MAX_VALUE) << 7);
        int i4 = 7;
        while (b < 0) {
            int i5 = i3 + 1;
            i4 += 7;
            j2 |= (r10 & Byte.MAX_VALUE) << i4;
            b = bArr[i3];
            i3 = i5;
        }
        c2776wA.b = j2;
        return i3;
    }

    public static int j(Object obj, InterfaceC3069v2 interfaceC3069v2, byte[] bArr, int i, int i2, int i3, C2776wA c2776wA) {
        C3035o2 c3035o2 = (C3035o2) interfaceC3069v2;
        int i4 = c2776wA.d + 1;
        c2776wA.d = i4;
        if (i4 >= 100) {
            throw new zzmm("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int iS = c3035o2.s(obj, bArr, i, i2, i3, c2776wA);
        c2776wA.d--;
        c2776wA.c = obj;
        return iS;
    }

    public static int k(Object obj, InterfaceC3069v2 interfaceC3069v2, byte[] bArr, int i, int i2, C2776wA c2776wA) {
        int iG = i + 1;
        int i3 = bArr[i];
        if (i3 < 0) {
            iG = g(i3, bArr, iG, c2776wA);
            i3 = c2776wA.a;
        }
        int i4 = iG;
        if (i3 < 0 || i3 > i2 - i4) {
            throw new zzmm("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        int i5 = c2776wA.d + 1;
        c2776wA.d = i5;
        if (i5 >= 100) {
            throw new zzmm("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i6 = i4 + i3;
        interfaceC3069v2.h(obj, bArr, i4, i6, c2776wA);
        c2776wA.d--;
        c2776wA.c = obj;
        return i6;
    }

    public static long l(int i, byte[] bArr) {
        return (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 6] & 255) << 48) | ((bArr[i + 7] & 255) << 56);
    }
}
