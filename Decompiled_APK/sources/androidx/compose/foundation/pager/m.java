package androidx.compose.foundation.pager;

import androidx.compose.runtime.L0;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class m implements androidx.compose.foundation.lazy.layout.r {
    public final C0466e a;
    public final int b;

    public m(C0466e c0466e, int i) {
        this.a = c0466e;
        this.b = i;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.r
    public final int a() {
        return Math.min(r0.l() - 1, ((C0472k) CollectionsKt.U(this.a.k().a)).a + this.b);
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final void b() {
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) ((L0) this.a.x).getValue();
        if (e != null) {
            e.k();
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.Collection] */
    @Override // androidx.compose.foundation.lazy.layout.r
    public final boolean c() {
        return !this.a.k().a.isEmpty();
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final int d() {
        return this.a.l();
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final int e() {
        return Math.max(0, this.a.d - this.b);
    }
}
