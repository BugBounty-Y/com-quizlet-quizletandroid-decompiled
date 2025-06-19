package com.google.android.gms.internal.ads;

import java.util.Collections;

/* loaded from: classes2.dex */
public final class Z {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public final int i;
    public final long j;
    public final Fi k;
    public final K4 l;

    public Z(int i, int i2, int i3, int i4, int i5, int i6, int i7, long j, Fi fi, K4 k4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = i5;
        this.f = d(i5);
        this.g = i6;
        this.h = i7;
        this.i = c(i7);
        this.j = j;
        this.k = fi;
        this.l = k4;
    }

    public static int c(int i) {
        if (i == 8) {
            return 1;
        }
        if (i == 12) {
            return 2;
        }
        if (i == 16) {
            return 4;
        }
        if (i == 20) {
            return 5;
        }
        if (i != 24) {
            return i != 32 ? -1 : 7;
        }
        return 6;
    }

    public static int d(int i) {
        switch (i) {
            case 8000:
                return 4;
            case 16000:
                return 5;
            case 22050:
                return 6;
            case 24000:
                return 7;
            case 32000:
                return 8;
            case 44100:
                return 9;
            case 48000:
                return 10;
            case 88200:
                return 1;
            case 96000:
                return 11;
            case 176400:
                return 2;
            case 192000:
                return 3;
            default:
                return -1;
        }
    }

    public final long a() {
        long j = this.j;
        if (j == 0) {
            return -9223372036854775807L;
        }
        return (j * 1000000) / this.e;
    }

    public final C1832aG b(byte[] bArr, K4 k4) {
        bArr[4] = Byte.MIN_VALUE;
        K4 k42 = this.l;
        if (k42 != null) {
            k4 = k42.b(k4);
        }
        EF ef = new EF();
        ef.d("audio/flac");
        int i = this.d;
        if (i <= 0) {
            i = -1;
        }
        ef.m = i;
        ef.B = this.g;
        ef.C = this.e;
        ef.D = Yo.r(this.h);
        ef.o = Collections.singletonList(bArr);
        ef.j = k4;
        return new C1832aG(ef);
    }

    public Z(int i, byte[] bArr) {
        C2466p0 c2466p0 = new C2466p0(bArr.length, bArr);
        c2466p0.s(i * 8);
        this.a = c2466p0.f(16);
        this.b = c2466p0.f(16);
        this.c = c2466p0.f(24);
        this.d = c2466p0.f(24);
        int iF = c2466p0.f(20);
        this.e = iF;
        this.f = d(iF);
        this.g = c2466p0.f(3) + 1;
        int iF2 = c2466p0.f(5) + 1;
        this.h = iF2;
        this.i = c(iF2);
        this.j = c2466p0.h(36);
        this.k = null;
        this.l = null;
    }
}
