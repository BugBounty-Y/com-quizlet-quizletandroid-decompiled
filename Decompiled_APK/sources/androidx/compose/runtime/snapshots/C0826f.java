package androidx.compose.runtime.snapshots;

import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.snapshots.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0826f extends h {
    public final Function1 e;
    public final h f;

    public C0826f(long j, l lVar, Function1 function1, h hVar) {
        super(j, lVar);
        this.e = function1;
        this.f = hVar;
        hVar.k();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void c() {
        if (this.c) {
            return;
        }
        long j = this.b;
        h hVar = this.f;
        if (j != hVar.g()) {
            a();
        }
        hVar.l();
        super.c();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final Function1 e() {
        return this.e;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final boolean f() {
        return true;
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
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void n(z zVar) {
        com.quizlet.data.repository.classfolder.e eVar = m.a;
        throw new IllegalStateException("Cannot modify a state object in a read-only snapshot");
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final h u(Function1 function1) {
        return new C0826f(this.b, this.a, m.l(function1, this.e, true), this.f);
    }
}
