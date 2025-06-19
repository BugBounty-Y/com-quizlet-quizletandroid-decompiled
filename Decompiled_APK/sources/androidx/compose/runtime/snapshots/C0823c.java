package androidx.compose.runtime.snapshots;

import androidx.compose.animation.U;
import androidx.compose.animation.core.C0268t0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.snapshots.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0823c extends C0824d {
    @Override // androidx.compose.runtime.snapshots.C0824d
    public final C0824d C(Function1 function1, Function1 function12) {
        return (C0824d) ((h) m.f(new C0268t0(2, new C0822b(function1, function12, 0))));
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void c() {
        synchronized (m.b) {
            o();
            Unit unit = Unit.a;
        }
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
        m.a();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final h u(Function1 function1) {
        return (g) ((h) m.f(new C0268t0(2, new U(3, function1))));
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    public final r w() {
        throw new IllegalStateException("Cannot apply the global snapshot directly. Call Snapshot.advanceGlobalSnapshot");
    }
}
