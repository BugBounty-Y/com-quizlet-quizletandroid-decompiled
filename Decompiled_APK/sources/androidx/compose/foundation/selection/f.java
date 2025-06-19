package androidx.compose.foundation.selection;

import androidx.compose.animation.core.K;
import androidx.compose.foundation.E;
import androidx.compose.foundation.InterfaceC0461p0;
import androidx.compose.foundation.interaction.l;
import androidx.compose.ui.semantics.h;
import androidx.compose.ui.semantics.r;
import androidx.compose.ui.semantics.t;
import androidx.compose.ui.semantics.u;
import androidx.compose.ui.semantics.v;
import kotlin.jvm.functions.Function1;
import kotlin.reflect.n;

/* loaded from: classes.dex */
public final class f extends E {
    public boolean H;
    public Function1 I;
    public final K J;

    public f(boolean z, l lVar, InterfaceC0461p0 interfaceC0461p0, boolean z2, h hVar, Function1 function1) {
        super(lVar, interfaceC0461p0, z2, null, hVar, new androidx.activity.compose.f(z, 2, function1));
        this.H = z;
        this.I = function1;
        this.J = new K(this, 8);
    }

    @Override // androidx.compose.foundation.AbstractC0368j
    public final void P0(v vVar) {
        androidx.compose.ui.state.a aVar = this.H ? androidx.compose.ui.state.a.a : androidx.compose.ui.state.a.b;
        n[] nVarArr = t.a;
        u uVar = r.B;
        n nVar = t.a[22];
        uVar.a(vVar, aVar);
    }
}
