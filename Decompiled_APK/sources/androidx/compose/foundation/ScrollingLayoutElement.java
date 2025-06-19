package androidx.compose.foundation;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class ScrollingLayoutElement extends androidx.compose.ui.node.T {
    public final N0 b;
    public final boolean c;

    public ScrollingLayoutElement(N0 n0, boolean z) {
        this.b = n0;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof ScrollingLayoutElement)) {
            return false;
        }
        ScrollingLayoutElement scrollingLayoutElement = (ScrollingLayoutElement) obj;
        return Intrinsics.b(this.b, scrollingLayoutElement.b) && this.c == scrollingLayoutElement.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.g(this.b.hashCode() * 31, 31, false);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        Q0 q0 = new Q0();
        q0.n = this.b;
        q0.o = this.c;
        return q0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        Q0 q0 = (Q0) pVar;
        q0.n = this.b;
        q0.o = this.c;
    }
}
