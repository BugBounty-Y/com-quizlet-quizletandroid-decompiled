package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.layout.InterfaceC0901w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.p0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0405p0 implements InterfaceC0901w, androidx.compose.ui.modifier.c, androidx.compose.ui.modifier.f {
    public final R0 b;
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;

    public C0405p0(R0 r0) {
        this.b = r0;
        this.c = C0776c.z(r0);
        this.d = C0776c.z(r0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C0405p0) {
            return Intrinsics.b(((C0405p0) obj).b, this.b);
        }
        return false;
    }

    @Override // androidx.compose.ui.modifier.f
    public final androidx.compose.ui.modifier.h getKey() {
        return U0.a;
    }

    @Override // androidx.compose.ui.modifier.f
    public final Object getValue() {
        return (R0) ((androidx.compose.runtime.L0) this.d).getValue();
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        InterfaceC0773a0 interfaceC0773a0 = this.c;
        int iD = ((R0) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).d(m, m.getLayoutDirection());
        int iA = ((R0) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).a(m);
        int iB = ((R0) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).b(m, m.getLayoutDirection()) + iD;
        int iC = ((R0) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).c(m) + iA;
        androidx.compose.ui.layout.W wB = j.B(L5.o(-iB, -iC, j2));
        return m.n0(L5.l(wB.a + iB, j2), L5.k(wB.b + iC, j2), kotlin.collections.V.c(), new androidx.compose.foundation.O0(wB, iD, iA, 1));
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.modifier.c
    public final void j(androidx.compose.ui.modifier.g gVar) {
        R0 r0 = (R0) gVar.d(U0.a);
        R0 r02 = this.b;
        ((androidx.compose.runtime.L0) this.c).setValue(new O(r02, r0));
        ((androidx.compose.runtime.L0) this.d).setValue(new M0(r0, r02));
    }
}
