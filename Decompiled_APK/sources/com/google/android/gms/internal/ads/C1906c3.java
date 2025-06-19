package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.c3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1906c3 {
    public final Eo a;
    public final Kn b;
    public boolean c;
    public boolean d;
    public boolean e;
    public long f;
    public long g;
    public long h;

    public C1906c3(int i) {
        switch (i) {
            case 1:
                this.a = new Eo();
                this.f = -9223372036854775807L;
                this.g = -9223372036854775807L;
                this.h = -9223372036854775807L;
                this.b = new Kn();
                break;
            default:
                this.a = new Eo();
                this.f = -9223372036854775807L;
                this.g = -9223372036854775807L;
                this.h = -9223372036854775807L;
                this.b = new Kn();
                break;
        }
    }

    public static long a(Kn kn) {
        int i = kn.b;
        if (kn.s() < 9) {
            return -9223372036854775807L;
        }
        byte[] bArr = new byte[9];
        kn.f(0, bArr, 9);
        kn.j(i);
        byte b = bArr[0];
        if ((b & 196) != 68) {
            return -9223372036854775807L;
        }
        byte b2 = bArr[2];
        if ((b2 & 4) != 4) {
            return -9223372036854775807L;
        }
        byte b3 = bArr[4];
        if ((b3 & 4) != 4 || (bArr[5] & 1) != 1 || (bArr[8] & 3) != 3) {
            return -9223372036854775807L;
        }
        long j = b;
        long j2 = b2;
        long j3 = (248 & j2) >> 3;
        long j4 = (j2 & 3) << 13;
        return j4 | ((bArr[1] & 255) << 20) | ((j & 3) << 28) | (((j & 56) >> 3) << 30) | (j3 << 15) | ((bArr[3] & 255) << 5) | ((b3 & 248) >> 3);
    }

    public static final int c(int i, byte[] bArr) {
        return (bArr[i + 3] & 255) | ((bArr[i] & 255) << 24) | ((bArr[i + 1] & 255) << 16) | ((bArr[i + 2] & 255) << 8);
    }

    public void b(P p) {
        byte[] bArr = Yo.b;
        int length = bArr.length;
        this.b.h(0, bArr);
        this.c = true;
        p.f = 0;
    }
}
