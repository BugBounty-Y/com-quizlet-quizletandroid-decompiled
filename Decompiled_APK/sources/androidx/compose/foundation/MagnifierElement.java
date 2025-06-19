package androidx.compose.foundation;

import android.view.View;
import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class MagnifierElement extends androidx.compose.ui.node.T {
    public final kotlin.jvm.internal.r b;
    public final kotlin.jvm.internal.r c;
    public final E0 d;

    /* JADX WARN: Multi-variable type inference failed */
    public MagnifierElement(Function1 function1, Function1 function12, E0 e0) {
        this.b = (kotlin.jvm.internal.r) function1;
        this.c = (kotlin.jvm.internal.r) function12;
        this.d = e0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MagnifierElement)) {
            return false;
        }
        kotlin.jvm.internal.r rVar = ((MagnifierElement) obj).b;
        return false;
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + androidx.compose.animation.d0.g(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(android.support.v4.media.session.a.b(this.b.hashCode() * 961, Float.NaN, 31), 31, true), 31, 9205357640488583168L), Float.NaN, 31), Float.NaN, 31), 31, true)) * 31);
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new s0(this.b, this.c, this.d);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        s0 s0Var = (s0) pVar;
        s0Var.getClass();
        E0 e0 = s0Var.p;
        View view = s0Var.q;
        androidx.compose.ui.unit.b bVar = s0Var.r;
        s0Var.n = this.b;
        s0Var.o = this.c;
        E0 e02 = this.d;
        s0Var.p = e02;
        View viewX = AbstractC0910f.x(s0Var);
        androidx.compose.ui.unit.b bVar2 = AbstractC0910f.v(s0Var).r;
        if (s0Var.s != null) {
            androidx.compose.ui.semantics.u uVar = t0.a;
            if (((!Float.isNaN(Float.NaN) || !Float.isNaN(Float.NaN)) && !e02.a()) || !androidx.compose.ui.unit.e.a(Float.NaN, Float.NaN) || !androidx.compose.ui.unit.e.a(Float.NaN, Float.NaN) || !e02.equals(e0) || !viewX.equals(view) || !Intrinsics.b(bVar2, bVar)) {
                s0Var.N0();
            }
        }
        s0Var.O0();
    }
}
