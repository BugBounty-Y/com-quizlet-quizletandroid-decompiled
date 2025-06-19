package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0407q0 implements z0 {
    public final R0 a;
    public final androidx.compose.ui.unit.b b;

    public C0407q0(R0 r0, androidx.compose.ui.unit.b bVar) {
        this.a = r0;
        this.b = bVar;
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float a() {
        R0 r0 = this.a;
        androidx.compose.ui.unit.b bVar = this.b;
        return bVar.O(r0.c(bVar));
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float b(androidx.compose.ui.unit.k kVar) {
        R0 r0 = this.a;
        androidx.compose.ui.unit.b bVar = this.b;
        return bVar.O(r0.d(bVar, kVar));
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float c(androidx.compose.ui.unit.k kVar) {
        R0 r0 = this.a;
        androidx.compose.ui.unit.b bVar = this.b;
        return bVar.O(r0.b(bVar, kVar));
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float d() {
        R0 r0 = this.a;
        androidx.compose.ui.unit.b bVar = this.b;
        return bVar.O(r0.a(bVar));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0407q0)) {
            return false;
        }
        C0407q0 c0407q0 = (C0407q0) obj;
        return Intrinsics.b(this.a, c0407q0.a) && Intrinsics.b(this.b, c0407q0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "InsetsPaddingValues(insets=" + this.a + ", density=" + this.b + ')';
    }
}
