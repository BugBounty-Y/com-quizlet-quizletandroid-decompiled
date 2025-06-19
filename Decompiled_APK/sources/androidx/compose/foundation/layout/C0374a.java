package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0374a implements R0 {
    public final R0 a;
    public final C0416v0 b;

    public C0374a(R0 r0, C0416v0 c0416v0) {
        this.a = r0;
        this.b = c0416v0;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int a(androidx.compose.ui.unit.b bVar) {
        return this.b.a(bVar) + this.a.a(bVar);
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int b(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        return this.b.b(bVar, kVar) + this.a.b(bVar, kVar);
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int c(androidx.compose.ui.unit.b bVar) {
        return this.b.c(bVar) + this.a.c(bVar);
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int d(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        return this.b.d(bVar, kVar) + this.a.d(bVar, kVar);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0374a)) {
            return false;
        }
        C0374a c0374a = (C0374a) obj;
        return Intrinsics.b(c0374a.a, this.a) && c0374a.b.equals(this.b);
    }

    public final int hashCode() {
        return (this.b.hashCode() * 31) + this.a.hashCode();
    }

    public final String toString() {
        return "(" + this.a + " + " + this.b + ')';
    }
}
