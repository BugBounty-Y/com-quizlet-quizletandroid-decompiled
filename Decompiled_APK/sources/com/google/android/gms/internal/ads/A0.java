package com.google.android.gms.internal.ads;

import androidx.compose.foundation.lazy.layout.C0429a;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* loaded from: classes2.dex */
public final class A0 implements U {
    public final /* synthetic */ int a;
    public final Kn b;
    public final C2208j0 c;

    public A0(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new Kn(4);
                this.c = new C2208j0(-1, -1, "image/heif");
                break;
            case 2:
                this.b = new Kn(4);
                this.c = new C2208j0(-1, -1, "image/webp");
                break;
            default:
                this.b = new Kn(4);
                this.c = new C2208j0(-1, -1, "image/avif");
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        switch (this.a) {
            case 0:
                ((P) v).n(4, false);
                P p = (P) v;
                Kn kn = this.b;
                kn.g(4);
                p.k(kn.a, 0, 4, false);
                if (kn.H() == 1718909296) {
                    kn.g(4);
                    p.k(kn.a, 0, 4, false);
                    if (kn.H() == 1635150182) {
                    }
                }
                break;
            case 1:
                ((P) v).n(4, false);
                P p2 = (P) v;
                Kn kn2 = this.b;
                kn2.g(4);
                p2.k(kn2.a, 0, 4, false);
                if (kn2.H() == 1718909296) {
                    kn2.g(4);
                    p2.k(kn2.a, 0, 4, false);
                    if (kn2.H() == 1751476579) {
                    }
                }
                break;
            default:
                Kn kn3 = this.b;
                kn3.g(4);
                P p3 = (P) v;
                p3.k(kn3.a, 0, 4, false);
                if (kn3.H() == 1380533830) {
                    p3.n(4, false);
                    kn3.g(4);
                    p3.k(kn3.a, 0, 4, false);
                    if (kn3.H() == 1464156752) {
                    }
                }
                break;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        switch (this.a) {
            case 0:
                this.c.e(w);
                break;
            case 1:
                this.c.e(w);
                break;
            default:
                this.c.e(w);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final int f(V v, C0429a c0429a) {
        switch (this.a) {
        }
        return this.c.f(v, c0429a);
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        switch (this.a) {
            case 0:
                this.c.h(j, j2);
                break;
            case 1:
                this.c.h(j, j2);
                break;
            default:
                this.c.h(j, j2);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        switch (this.a) {
            case 0:
                C2244ju c2244ju = AbstractC2330lu.b;
                break;
            case 1:
                C2244ju c2244ju2 = AbstractC2330lu.b;
                break;
            default:
                C2244ju c2244ju3 = AbstractC2330lu.b;
                break;
        }
        return Bu.e;
    }
}
