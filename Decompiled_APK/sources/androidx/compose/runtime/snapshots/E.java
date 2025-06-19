package androidx.compose.runtime.snapshots;

import androidx.collection.J;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class E extends C0824d {
    public final C0824d o;
    public final boolean p;
    public final boolean q;
    public Function1 r;
    public Function1 s;
    public final long t;

    /* JADX WARN: Illegal instructions before constructor call */
    public E(C0824d c0824d, Function1 function1, Function1 function12, boolean z, boolean z2) {
        Function1 function1I;
        Function1 function1Y;
        com.quizlet.data.repository.classfolder.e eVar = m.a;
        super(0L, l.e, m.l(function1, (c0824d == null || (function1Y = c0824d.e()) == null) ? m.i.e : function1Y, z), m.b(function12, (c0824d == null || (function1I = c0824d.i()) == null) ? m.i.f : function1I));
        this.o = c0824d;
        this.p = z;
        this.q = z2;
        this.r = this.e;
        this.s = this.f;
        this.t = androidx.compose.runtime.internal.e.c();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    public final void B(J j) {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    public final C0824d C(Function1 function1, Function1 function12) {
        Function1 function1L = m.l(function1, this.r, true);
        Function1 function1B = m.b(function12, this.s);
        return !this.p ? new E(D().C(null, function1B), function1L, function1B, false, true) : D().C(function1L, function1B);
    }

    public final C0824d D() {
        C0824d c0824d = this.o;
        return c0824d == null ? m.i : c0824d;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void c() {
        C0824d c0824d;
        this.c = true;
        if (!this.q || (c0824d = this.o) == null) {
            return;
        }
        c0824d.c();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final l d() {
        return D().d();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final Function1 e() {
        return this.r;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final boolean f() {
        return D().f();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final long g() {
        return D().g();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final int h() {
        return D().h();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final Function1 i() {
        return this.s;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void k() {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void l() {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void m() {
        D().m();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void n(z zVar) {
        D().n(zVar);
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void r(l lVar) {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void s(long j) {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void t(int i) {
        D().t(i);
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final h u(Function1 function1) {
        Function1 function1L = m.l(function1, this.r, true);
        return !this.p ? m.h(D().u(null), function1L, true) : D().u(function1L);
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    public final r w() {
        return D().w();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    public final J x() {
        return D().x();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    /* renamed from: y */
    public final Function1 e() {
        return this.r;
    }
}
