package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0420z implements InterfaceC0417w {
    public final androidx.compose.ui.layout.f0 a;
    public final long b;

    public C0420z(androidx.compose.ui.layout.f0 f0Var, long j) {
        this.a = f0Var;
        this.b = j;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0417w
    public final androidx.compose.ui.q a(androidx.compose.ui.q qVar, androidx.compose.ui.i iVar) {
        return qVar.g(new BoxChildDataElement(iVar, false));
    }

    public final float b() {
        long j = this.b;
        if (!androidx.compose.ui.unit.a.d(j)) {
            return Float.POSITIVE_INFINITY;
        }
        return this.a.O(androidx.compose.ui.unit.a.h(j));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0420z)) {
            return false;
        }
        C0420z c0420z = (C0420z) obj;
        return Intrinsics.b(this.a, c0420z.a) && androidx.compose.ui.unit.a.b(this.b, c0420z.b);
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "BoxWithConstraintsScopeImpl(density=" + this.a + ", constraints=" + ((Object) androidx.compose.ui.unit.a.l(this.b)) + ')';
    }
}
