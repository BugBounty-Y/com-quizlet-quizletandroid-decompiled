package androidx.compose.runtime.snapshots;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F extends h {
    public final h e;
    public final boolean f;
    public Function1 g;
    public final long h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(h hVar, Function1 function1, boolean z) {
        Function1 function1E;
        super(0L, l.e);
        com.quizlet.data.repository.classfolder.e eVar = m.a;
        this.e = hVar;
        this.f = z;
        this.g = m.l(function1, (hVar == null || (function1E = hVar.e()) == null) ? m.i.e : function1E, false);
        this.h = androidx.compose.runtime.internal.e.c();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void c() {
        h hVar;
        this.c = true;
        if (!this.f || (hVar = this.e) == null) {
            return;
        }
        hVar.c();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final l d() {
        return v().d();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final Function1 e() {
        return this.g;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final boolean f() {
        return v().f();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final long g() {
        return v().g();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final Function1 i() {
        return null;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void k() {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void l() {
        r.h();
        throw null;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void m() {
        v().m();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void n(z zVar) {
        v().n(zVar);
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final h u(Function1 function1) {
        return m.h(v().u(null), m.l(function1, this.g, true), true);
    }

    public final h v() {
        h hVar = this.e;
        return hVar == null ? m.i : hVar;
    }
}
