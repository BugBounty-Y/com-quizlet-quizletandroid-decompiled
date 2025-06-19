package androidx.compose.foundation.lazy.grid;

import androidx.compose.ui.node.E;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class d implements androidx.compose.foundation.lazy.layout.r {
    public final A a;

    public d(A a) {
        this.a = a;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.r
    public final int a() {
        return ((r) CollectionsKt.U(this.a.g().g)).a;
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final void b() {
        E e = this.a.h;
        if (e != null) {
            e.k();
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.Collection] */
    @Override // androidx.compose.foundation.lazy.layout.r
    public final boolean c() {
        return !this.a.g().g.isEmpty();
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final int d() {
        return this.a.g().j;
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final int e() {
        return this.a.b.a();
    }
}
