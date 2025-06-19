package com.google.android.gms.internal.ads;

import android.view.Surface;
import androidx.compose.ui.text.input.C1007j;
import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2077g implements E {
    public final C2722v a;
    public final C2894z b;
    public final ArrayDeque c;
    public Surface d;
    public C1832aG e;
    public long f;
    public long g;
    public D h;
    public Executor i;
    public InterfaceC2636t j;

    public C2077g(C2722v c2722v, C1847ao c1847ao) {
        this.a = c2722v;
        c2722v.k = c1847ao;
        this.b = new C2894z(new C1732Mb(this), c2722v);
        this.c = new ArrayDeque();
        this.e = new C1832aG(new EF());
        this.f = -9223372036854775807L;
        this.h = D.N0;
        this.i = new ExecutorC1902c();
        this.j = new C1946d(0);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void B() {
        this.a.c();
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void E(boolean z) {
        if (z) {
            C2722v c2722v = this.a;
            C2851y c2851y = c2722v.b;
            c2851y.m = 0L;
            c2851y.p = -1L;
            c2851y.n = -1L;
            c2722v.g = -9223372036854775807L;
            c2722v.e = -9223372036854775807L;
            c2722v.d = Math.min(c2722v.d, 1);
            c2722v.h = -9223372036854775807L;
        }
        C2894z c2894z = this.b;
        C1007j c1007j = c2894z.e;
        c1007j.b = 0;
        c1007j.c = -1;
        c1007j.d = 0;
        c2894z.f = -9223372036854775807L;
        c2894z.g = -9223372036854775807L;
        c2894z.h = -9223372036854775807L;
        androidx.compose.ui.text.android.selection.f fVar = c2894z.d;
        if (fVar.o() > 0) {
            AbstractC1795We.B(fVar.o() > 0);
            while (fVar.o() > 1) {
                fVar.p();
            }
            Object objP = fVar.p();
            objP.getClass();
            c2894z.j = ((Long) objP).longValue();
        }
        androidx.compose.ui.text.android.selection.f fVar2 = c2894z.c;
        if (fVar2.o() > 0) {
            AbstractC1795We.B(fVar2.o() > 0);
            while (fVar2.o() > 1) {
                fVar2.p();
            }
            Object objP2 = fVar2.p();
            objP2.getClass();
            fVar2.s(0L, (C1740Nd) objP2);
        }
        this.c.clear();
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void G() {
        C2894z c2894z = this.b;
        long j = c2894z.f;
        if (j == -9223372036854775807L) {
            j = Long.MIN_VALUE;
            c2894z.f = Long.MIN_VALUE;
            c2894z.g = Long.MIN_VALUE;
        }
        c2894z.h = j;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void H(Surface surface, Pn pn) {
        this.d = surface;
        this.a.f(surface);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean I(long j, C2207j c2207j) {
        this.c.add(c2207j);
        long j2 = j - this.g;
        C2894z c2894z = this.b;
        C1007j c1007j = c2894z.e;
        int i = c1007j.d;
        long[] jArr = (long[]) c1007j.f;
        int length = jArr.length;
        if (i == length) {
            int i2 = length + length;
            if (i2 < 0) {
                throw new IllegalStateException();
            }
            long[] jArr2 = new long[i2];
            int i3 = c1007j.b;
            int i4 = length - i3;
            System.arraycopy(jArr, i3, jArr2, 0, i4);
            System.arraycopy((long[]) c1007j.f, 0, jArr2, i4, i3);
            c1007j.b = 0;
            c1007j.c = c1007j.d - 1;
            c1007j.f = jArr2;
            c1007j.e = i2 - 1;
            jArr = jArr2;
        }
        int i5 = (c1007j.c + 1) & c1007j.e;
        c1007j.c = i5;
        jArr[i5] = j2;
        c1007j.d++;
        c2894z.f = j2;
        c2894z.h = -9223372036854775807L;
        this.i.execute(new RunnableC1989e(this, 0));
        return true;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void J(long j, long j2) {
        try {
            this.b.a(j, j2);
        } catch (zzik e) {
            throw new zzacg(e, this.e);
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean K() {
        C2894z c2894z = this.b;
        long j = c2894z.h;
        return j != -9223372036854775807L && c2894z.g == j;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean L(C1832aG c1832aG) {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void M(float f) {
        this.a.g(f);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void N(boolean z) {
        C2722v c2722v = this.a;
        c2722v.i = z;
        c2722v.h = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void O(InterfaceC2636t interfaceC2636t) {
        this.j = interfaceC2636t;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void P(C1832aG c1832aG, long j, int i, List list) {
        long j2;
        AbstractC1795We.L(list.isEmpty());
        C1832aG c1832aG2 = this.e;
        int i2 = c1832aG2.t;
        int i3 = c1832aG.t;
        C2894z c2894z = this.b;
        int i4 = c1832aG.u;
        if (i3 == i2 && i4 == c1832aG2.u) {
            j2 = 1;
        } else {
            long j3 = c2894z.f;
            j2 = 1;
            c2894z.c.s(j3 == -9223372036854775807L ? 0L : j3 + 1, new C1740Nd(i3, 1.0f, i4));
        }
        float f = this.e.v;
        float f2 = c1832aG.v;
        if (f2 != f) {
            this.a.e(f2);
        }
        this.e = c1832aG;
        if (j != this.f) {
            if (c2894z.e.d == 0) {
                c2894z.a.d(i);
                c2894z.j = j;
            } else {
                long j4 = c2894z.f;
                c2894z.d.s(j4 != -9223372036854775807L ? j4 + j2 : 0L, Long.valueOf(j));
            }
            this.f = j;
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void Q() {
        this.a.b();
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void R(int i) {
        C2851y c2851y = this.a.b;
        if (c2851y.j == i) {
            return;
        }
        c2851y.j = i;
        c2851y.d(true);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void S(Ts ts) {
        Kv kv = Kv.a;
        this.h = ts;
        this.i = kv;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean T() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean U(boolean z) {
        return this.a.h(z);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void V(long j) {
        this.g = j;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void W(List list) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void g() {
        C2722v c2722v = this.a;
        if (c2722v.d == 0) {
            c2722v.d = 1;
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void l() {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void m() {
    }

    @Override // com.google.android.gms.internal.ads.E
    public final Surface zzb() {
        Surface surface = this.d;
        AbstractC1795We.p(surface);
        return surface;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void zzi() {
        this.d = null;
        this.a.f(null);
    }
}
