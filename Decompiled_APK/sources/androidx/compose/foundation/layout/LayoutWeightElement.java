package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class LayoutWeightElement extends androidx.compose.ui.node.T {
    public final float b;
    public final boolean c;

    public LayoutWeightElement(float f, boolean z) {
        this.b = f;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        LayoutWeightElement layoutWeightElement = obj instanceof LayoutWeightElement ? (LayoutWeightElement) obj : null;
        return layoutWeightElement != null && this.b == layoutWeightElement.b && this.c == layoutWeightElement.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + (Float.hashCode(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0414u0 c0414u0 = new C0414u0();
        c0414u0.n = this.b;
        c0414u0.o = this.c;
        return c0414u0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0414u0 c0414u0 = (C0414u0) pVar;
        c0414u0.n = this.b;
        c0414u0.o = this.c;
    }
}
