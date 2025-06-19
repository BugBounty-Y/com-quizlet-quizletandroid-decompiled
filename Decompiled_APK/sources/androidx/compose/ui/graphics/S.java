package androidx.compose.ui.graphics;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class S implements androidx.compose.ui.unit.b {
    public int a;
    public float b;
    public float c;
    public float d;
    public float e;
    public float f;
    public float g;
    public long h;
    public long i;
    public float j;
    public float k;
    public float l;
    public float m;
    public long n;
    public V o;
    public boolean p;
    public int q;
    public long r;
    public androidx.compose.ui.unit.b s;
    public androidx.compose.ui.unit.k t;
    public C0856p u;
    public N v;

    public final void B(float f) {
        if (this.f == f) {
            return;
        }
        this.a |= 16;
        this.f = f;
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.s.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.s.a();
    }

    public final void b(float f) {
        if (this.d == f) {
            return;
        }
        this.a |= 4;
        this.d = f;
    }

    public final void c(long j) {
        if (C0861v.c(this.h, j)) {
            return;
        }
        this.a |= 64;
        this.h = j;
    }

    public final void d(float f) {
        if (this.m == f) {
            return;
        }
        this.a |= 2048;
        this.m = f;
    }

    public final void e(boolean z) {
        if (this.p != z) {
            this.a |= 16384;
            this.p = z;
        }
    }

    public final void f(P p) {
        if (Intrinsics.b(this.u, p)) {
            return;
        }
        this.a |= 131072;
        this.u = (C0856p) p;
    }

    public final void h(float f) {
        if (this.j == f) {
            return;
        }
        this.a |= 256;
        this.j = f;
    }

    public final void i(float f) {
        if (this.k == f) {
            return;
        }
        this.a |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        this.k = f;
    }

    public final void k(float f) {
        if (this.l == f) {
            return;
        }
        this.a |= 1024;
        this.l = f;
    }

    public final void m(float f) {
        if (this.b == f) {
            return;
        }
        this.a |= 1;
        this.b = f;
    }

    public final void o(float f) {
        if (this.c == f) {
            return;
        }
        this.a |= 2;
        this.c = f;
    }

    public final void p(float f) {
        if (this.g == f) {
            return;
        }
        this.a |= 32;
        this.g = f;
    }

    public final void t(V v) {
        if (Intrinsics.b(this.o, v)) {
            return;
        }
        this.a |= 8192;
        this.o = v;
    }

    public final void u(long j) {
        if (C0861v.c(this.i, j)) {
            return;
        }
        this.a |= 128;
        this.i = j;
    }

    public final void x(long j) {
        if (Z.a(this.n, j)) {
            return;
        }
        this.a |= 4096;
        this.n = j;
    }

    public final void z(float f) {
        if (this.e == f) {
            return;
        }
        this.a |= 8;
        this.e = f;
    }
}
