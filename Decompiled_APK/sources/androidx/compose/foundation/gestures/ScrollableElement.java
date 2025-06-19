package androidx.compose.foundation.gestures;

import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class ScrollableElement extends androidx.compose.ui.node.T {
    public final E0 b;
    public final EnumC0320d0 c;
    public final androidx.compose.foundation.C0 d;
    public final boolean e;
    public final boolean f;
    public final InterfaceC0314a0 g;
    public final androidx.compose.foundation.interaction.l h;
    public final InterfaceC0319d i;

    public ScrollableElement(androidx.compose.foundation.C0 c0, InterfaceC0319d interfaceC0319d, InterfaceC0314a0 interfaceC0314a0, EnumC0320d0 enumC0320d0, E0 e0, androidx.compose.foundation.interaction.l lVar, boolean z, boolean z2) {
        this.b = e0;
        this.c = enumC0320d0;
        this.d = c0;
        this.e = z;
        this.f = z2;
        this.g = interfaceC0314a0;
        this.h = lVar;
        this.i = interfaceC0319d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ScrollableElement)) {
            return false;
        }
        ScrollableElement scrollableElement = (ScrollableElement) obj;
        return Intrinsics.b(this.b, scrollableElement.b) && this.c == scrollableElement.c && Intrinsics.b(this.d, scrollableElement.d) && this.e == scrollableElement.e && this.f == scrollableElement.f && Intrinsics.b(this.g, scrollableElement.g) && Intrinsics.b(this.h, scrollableElement.h) && Intrinsics.b(this.i, scrollableElement.i);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + (this.b.hashCode() * 31)) * 31;
        androidx.compose.foundation.C0 c0 = this.d;
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.g((iHashCode + (c0 != null ? c0.hashCode() : 0)) * 31, 31, this.e), 31, this.f);
        InterfaceC0314a0 interfaceC0314a0 = this.g;
        int iHashCode2 = (iG + (interfaceC0314a0 != null ? interfaceC0314a0.hashCode() : 0)) * 31;
        androidx.compose.foundation.interaction.l lVar = this.h;
        int iHashCode3 = (iHashCode2 + (lVar != null ? lVar.hashCode() : 0)) * 31;
        InterfaceC0319d interfaceC0319d = this.i;
        return iHashCode3 + (interfaceC0319d != null ? interfaceC0319d.hashCode() : 0);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        androidx.compose.foundation.interaction.l lVar = this.h;
        return new D0(this.d, this.i, this.g, this.c, this.b, lVar, this.e, this.f);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        boolean z;
        D0 d0 = (D0) pVar;
        boolean z2 = d0.r;
        boolean z3 = this.e;
        boolean z4 = true;
        boolean z5 = false;
        if (z2 != z3) {
            d0.D.b = z3;
            d0.A.n = z3;
            z = true;
        } else {
            z = false;
        }
        InterfaceC0314a0 interfaceC0314a0 = this.g;
        InterfaceC0314a0 interfaceC0314a02 = interfaceC0314a0 == null ? d0.B : interfaceC0314a0;
        L0 l0 = d0.C;
        E0 e0 = l0.a;
        E0 e02 = this.b;
        if (!Intrinsics.b(e0, e02)) {
            l0.a = e02;
            z5 = true;
        }
        androidx.compose.foundation.C0 c0 = this.d;
        l0.b = c0;
        EnumC0320d0 enumC0320d0 = l0.d;
        EnumC0320d0 enumC0320d02 = this.c;
        if (enumC0320d0 != enumC0320d02) {
            l0.d = enumC0320d02;
            z5 = true;
        }
        boolean z6 = l0.e;
        boolean z7 = this.f;
        if (z6 != z7) {
            l0.e = z7;
        } else {
            z4 = z5;
        }
        l0.c = interfaceC0314a02;
        l0.f = d0.z;
        C0333k c0333k = d0.E;
        c0333k.n = enumC0320d02;
        c0333k.p = z7;
        c0333k.q = this.i;
        d0.x = c0;
        d0.y = interfaceC0314a0;
        boolean z8 = z4;
        C0321e c0321e = C0321e.e;
        EnumC0320d0 enumC0320d03 = l0.d;
        EnumC0320d0 enumC0320d04 = EnumC0320d0.a;
        if (enumC0320d03 != enumC0320d04) {
            enumC0320d04 = EnumC0320d0.b;
        }
        d0.X0(c0321e, z3, this.h, enumC0320d04, z8);
        if (z) {
            d0.G = null;
            d0.H = null;
            AbstractC0910f.p(d0);
        }
    }
}
