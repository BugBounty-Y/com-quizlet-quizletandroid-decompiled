package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import java.util.List;

/* loaded from: classes2.dex */
public final class GD {
    public static final C2093gF t = new C2093gF(-1, new Object());
    public final A9 a;
    public final C2093gF b;
    public final long c;
    public final long d;
    public final int e;
    public final zzik f;
    public final boolean g;
    public final HF h;
    public final YF i;
    public final List j;
    public final C2093gF k;
    public final boolean l;
    public final int m;
    public final int n;
    public final C2040f6 o;
    public volatile long p;
    public volatile long q;
    public volatile long r;
    public volatile long s;

    public GD(A9 a9, C2093gF c2093gF, long j, long j2, int i, zzik zzikVar, boolean z, HF hf, YF yf, List list, C2093gF c2093gF2, boolean z2, int i2, int i3, C2040f6 c2040f6, long j3, long j4, long j5, long j6) {
        this.a = a9;
        this.b = c2093gF;
        this.c = j;
        this.d = j2;
        this.e = i;
        this.f = zzikVar;
        this.g = z;
        this.h = hf;
        this.i = yf;
        this.j = list;
        this.k = c2093gF2;
        this.l = z2;
        this.m = i2;
        this.n = i3;
        this.o = c2040f6;
        this.p = j3;
        this.q = j4;
        this.r = j5;
        this.s = j6;
    }

    public static GD h(YF yf) {
        X8 x8 = A9.a;
        C2093gF c2093gF = t;
        return new GD(x8, c2093gF, -9223372036854775807L, 0L, 1, null, false, HF.d, yf, Bu.e, c2093gF, false, 1, 0, C2040f6.d, 0L, 0L, 0L, 0L);
    }

    public final GD a(boolean z) {
        return new GD(this.a, this.b, this.c, this.d, this.e, this.f, z, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s);
    }

    public final GD b(C2093gF c2093gF) {
        return new GD(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, c2093gF, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s);
    }

    public final GD c(C2093gF c2093gF, long j, long j2, long j3, long j4, HF hf, YF yf, List list) {
        C2093gF c2093gF2 = this.k;
        boolean z = this.l;
        int i = this.m;
        int i2 = this.n;
        C2040f6 c2040f6 = this.o;
        long j5 = this.p;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        return new GD(this.a, c2093gF, j2, j3, this.e, this.f, this.g, hf, yf, list, c2093gF2, z, i, i2, c2040f6, j5, j4, j, jElapsedRealtime);
    }

    public final GD d(int i, int i2, boolean z) {
        return new GD(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, z, i, i2, this.o, this.p, this.q, this.r, this.s);
    }

    public final GD e(zzik zzikVar) {
        return new GD(this.a, this.b, this.c, this.d, this.e, zzikVar, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s);
    }

    public final GD f(int i) {
        return new GD(this.a, this.b, this.c, this.d, i, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s);
    }

    public final GD g(A9 a9) {
        return new GD(a9, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s);
    }

    public final boolean i() {
        return this.e == 3 && this.l && this.n == 0;
    }
}
