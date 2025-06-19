package androidx.compose.foundation.layout;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;

@Metadata
/* loaded from: classes.dex */
final class PaddingElement extends androidx.compose.ui.node.T {
    public final float b;
    public final float c;
    public final float d;
    public final float e;

    public PaddingElement(float f, float f2, float f3, float f4, Function1 function1) {
        this.b = f;
        this.c = f2;
        this.d = f3;
        this.e = f4;
        if ((f < DefinitionKt.NO_Float_VALUE && !androidx.compose.ui.unit.e.a(f, Float.NaN)) || ((f2 < DefinitionKt.NO_Float_VALUE && !androidx.compose.ui.unit.e.a(f2, Float.NaN)) || ((f3 < DefinitionKt.NO_Float_VALUE && !androidx.compose.ui.unit.e.a(f3, Float.NaN)) || (f4 < DefinitionKt.NO_Float_VALUE && !androidx.compose.ui.unit.e.a(f4, Float.NaN))))) {
            throw new IllegalArgumentException("Padding must be non-negative");
        }
    }

    public final boolean equals(Object obj) {
        PaddingElement paddingElement = obj instanceof PaddingElement ? (PaddingElement) obj : null;
        return paddingElement != null && androidx.compose.ui.unit.e.a(this.b, paddingElement.b) && androidx.compose.ui.unit.e.a(this.c, paddingElement.c) && androidx.compose.ui.unit.e.a(this.d, paddingElement.d) && androidx.compose.ui.unit.e.a(this.e, paddingElement.e);
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.b) * 31, this.c, 31), this.d, 31), this.e, 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        y0 y0Var = new y0();
        y0Var.n = this.b;
        y0Var.o = this.c;
        y0Var.p = this.d;
        y0Var.q = this.e;
        y0Var.r = true;
        return y0Var;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        y0 y0Var = (y0) pVar;
        y0Var.n = this.b;
        y0Var.o = this.c;
        y0Var.p = this.d;
        y0Var.q = this.e;
        y0Var.r = true;
    }
}
