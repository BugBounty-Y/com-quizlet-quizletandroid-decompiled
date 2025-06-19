package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class UnspecifiedConstraintsElement extends androidx.compose.ui.node.T {
    public final float b;
    public final float c;

    public UnspecifiedConstraintsElement(float f, float f2) {
        this.b = f;
        this.c = f2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof UnspecifiedConstraintsElement)) {
            return false;
        }
        UnspecifiedConstraintsElement unspecifiedConstraintsElement = (UnspecifiedConstraintsElement) obj;
        return androidx.compose.ui.unit.e.a(this.b, unspecifiedConstraintsElement.b) && androidx.compose.ui.unit.e.a(this.c, unspecifiedConstraintsElement.c);
    }

    public final int hashCode() {
        return Float.hashCode(this.c) + (Float.hashCode(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        O0 o0 = new O0();
        o0.n = this.b;
        o0.o = this.c;
        return o0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        O0 o0 = (O0) pVar;
        o0.n = this.b;
        o0.o = this.c;
    }
}
