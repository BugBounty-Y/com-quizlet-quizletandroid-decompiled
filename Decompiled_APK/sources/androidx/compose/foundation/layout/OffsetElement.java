package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class OffsetElement extends androidx.compose.ui.node.T {
    public final float b;
    public final float c;

    public OffsetElement(float f, float f2, C0406q c0406q) {
        this.b = f;
        this.c = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        OffsetElement offsetElement = obj instanceof OffsetElement ? (OffsetElement) obj : null;
        return offsetElement != null && androidx.compose.ui.unit.e.a(this.b, offsetElement.b) && androidx.compose.ui.unit.e.a(this.c, offsetElement.c);
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + android.support.v4.media.session.a.b(Float.hashCode(this.b) * 31, this.c, 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        w0 w0Var = new w0();
        w0Var.n = this.b;
        w0Var.o = this.c;
        w0Var.p = true;
        return w0Var;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        w0 w0Var = (w0) pVar;
        w0Var.n = this.b;
        w0Var.o = this.c;
        w0Var.p = true;
    }

    public final String toString() {
        return "OffsetModifierElement(x=" + ((Object) androidx.compose.ui.unit.e.b(this.b)) + ", y=" + ((Object) androidx.compose.ui.unit.e.b(this.c)) + ", rtlAware=true)";
    }
}
