package androidx.compose.foundation;

import androidx.compose.foundation.gestures.i1;
import androidx.compose.foundation.gestures.k1;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class J extends AbstractC0368j {
    public Function0 H;

    @Override // androidx.compose.foundation.AbstractC0368j
    public final void P0(androidx.compose.ui.semantics.v vVar) {
        if (this.H != null) {
            androidx.compose.animation.core.K k = new androidx.compose.animation.core.K(this, 3);
            kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
            ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.j.c, new androidx.compose.ui.semantics.a(null, k));
        }
    }

    @Override // androidx.compose.foundation.AbstractC0368j
    public final Object Q0(androidx.compose.ui.input.pointer.B b, C0366i c0366i) {
        int i = 1;
        kotlin.coroutines.h hVar = null;
        I i2 = (!this.t || this.H == null) ? null : new I(this, 0);
        D d = new D(this, hVar, i);
        I i3 = new I(this, 1);
        androidx.compose.foundation.gestures.S s = k1.a;
        Object objM = kotlinx.coroutines.E.m(new i1(b, d, i2, null, i3, null), c0366i);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objM != aVar) {
            objM = Unit.a;
        }
        return objM == aVar ? objM : Unit.a;
    }
}
