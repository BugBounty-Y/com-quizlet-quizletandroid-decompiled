package androidx.compose.runtime.snapshots;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class g extends h {
    public final Function1 e;
    public int f;

    public g(long j, l lVar, Function1 function1) {
        super(j, lVar);
        this.e = function1;
        this.f = 1;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void c() {
        if (this.c) {
            return;
        }
        l();
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
        this.f++;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void l() {
        int i = this.f - 1;
        this.f = i;
        if (i == 0) {
            a();
        }
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
        m.d(this);
        return new C0826f(this.b, this.a, m.l(function1, this.e, true), this);
    }
}
