package androidx.compose.foundation.lazy;

import kotlin.collections.CollectionsKt;

/* renamed from: androidx.compose.foundation.lazy.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0424d implements androidx.compose.foundation.lazy.layout.r {
    public final A a;

    public C0424d(A a) {
        this.a = a;
    }

    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.r
    public final int a() {
        return Math.min(d() - 1, ((r) CollectionsKt.U(this.a.h().j)).a);
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final void b() {
        androidx.compose.ui.node.E e = this.a.k;
        if (e != null) {
            e.k();
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.Collection] */
    @Override // androidx.compose.foundation.lazy.layout.r
    public final boolean c() {
        return !this.a.h().j.isEmpty();
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final int d() {
        return this.a.h().m;
    }

    @Override // androidx.compose.foundation.lazy.layout.r
    public final int e() {
        return Math.max(0, this.a.d.a());
    }
}
