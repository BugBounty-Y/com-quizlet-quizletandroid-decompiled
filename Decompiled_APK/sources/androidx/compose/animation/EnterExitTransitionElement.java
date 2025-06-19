package androidx.compose.animation;

import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.w0;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class EnterExitTransitionElement extends androidx.compose.ui.node.T {
    public final E0 b;
    public final w0 c;
    public final w0 d;
    public final w0 e;
    public final a0 f;
    public final b0 g;
    public final Function0 h;
    public final P i;

    public EnterExitTransitionElement(E0 e0, w0 w0Var, w0 w0Var2, w0 w0Var3, a0 a0Var, b0 b0Var, Function0 function0, P p) {
        this.b = e0;
        this.c = w0Var;
        this.d = w0Var2;
        this.e = w0Var3;
        this.f = a0Var;
        this.g = b0Var;
        this.h = function0;
        this.i = p;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof EnterExitTransitionElement)) {
            return false;
        }
        EnterExitTransitionElement enterExitTransitionElement = (EnterExitTransitionElement) obj;
        return Intrinsics.b(this.b, enterExitTransitionElement.b) && Intrinsics.b(this.c, enterExitTransitionElement.c) && Intrinsics.b(this.d, enterExitTransitionElement.d) && Intrinsics.b(this.e, enterExitTransitionElement.e) && Intrinsics.b(this.f, enterExitTransitionElement.f) && Intrinsics.b(this.g, enterExitTransitionElement.g) && Intrinsics.b(this.h, enterExitTransitionElement.h) && Intrinsics.b(this.i, enterExitTransitionElement.i);
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        w0 w0Var = this.c;
        int iHashCode2 = (iHashCode + (w0Var == null ? 0 : w0Var.hashCode())) * 31;
        w0 w0Var2 = this.d;
        int iHashCode3 = (iHashCode2 + (w0Var2 == null ? 0 : w0Var2.hashCode())) * 31;
        w0 w0Var3 = this.e;
        return this.i.hashCode() + ((this.h.hashCode() + ((this.g.a.hashCode() + ((this.f.a.hashCode() + ((iHashCode3 + (w0Var3 != null ? w0Var3.hashCode() : 0)) * 31)) * 31)) * 31)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new Z(this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        Z z = (Z) pVar;
        z.o = this.b;
        z.p = this.c;
        z.q = this.d;
        z.r = this.e;
        z.s = this.f;
        z.t = this.g;
        z.u = this.h;
        z.v = this.i;
    }

    public final String toString() {
        return "EnterExitTransitionElement(transition=" + this.b + ", sizeAnimation=" + this.c + ", offsetAnimation=" + this.d + ", slideAnimation=" + this.e + ", enter=" + this.f + ", exit=" + this.g + ", isEnabled=" + this.h + ", graphicsLayerBlock=" + this.i + ')';
    }
}
