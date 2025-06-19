package androidx.compose.foundation;

import androidx.compose.foundation.gestures.InterfaceC0314a0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class ScrollSemanticsElement extends androidx.compose.ui.node.T {
    public final N0 b;
    public final InterfaceC0314a0 c;
    public final boolean d;
    public final boolean e;

    public ScrollSemanticsElement(N0 n0, InterfaceC0314a0 interfaceC0314a0, boolean z, boolean z2) {
        this.b = n0;
        this.c = interfaceC0314a0;
        this.d = z;
        this.e = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ScrollSemanticsElement)) {
            return false;
        }
        ScrollSemanticsElement scrollSemanticsElement = (ScrollSemanticsElement) obj;
        return Intrinsics.b(this.b, scrollSemanticsElement.b) && Intrinsics.b(this.c, scrollSemanticsElement.c) && this.d == scrollSemanticsElement.d && this.e == scrollSemanticsElement.e;
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(this.b.hashCode() * 31, 31, false);
        InterfaceC0314a0 interfaceC0314a0 = this.c;
        return Boolean.hashCode(this.e) + androidx.compose.animation.d0.g((iG + (interfaceC0314a0 != null ? interfaceC0314a0.hashCode() : 0)) * 31, 31, this.d);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        K0 k0 = new K0();
        k0.n = this.b;
        k0.o = this.e;
        return k0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        K0 k0 = (K0) pVar;
        k0.n = this.b;
        k0.o = this.e;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ScrollSemanticsElement(state=");
        sb.append(this.b);
        sb.append(", reverseScrolling=false, flingBehavior=");
        sb.append(this.c);
        sb.append(", isScrollable=");
        sb.append(this.d);
        sb.append(", isVertical=");
        return android.support.v4.media.session.a.u(sb, this.e, ')');
    }
}
