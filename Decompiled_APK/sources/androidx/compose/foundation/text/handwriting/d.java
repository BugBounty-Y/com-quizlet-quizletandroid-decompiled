package androidx.compose.foundation.text.handwriting;

import androidx.compose.foundation.O0;
import androidx.compose.ui.focus.s;
import androidx.compose.ui.input.pointer.B;
import androidx.compose.ui.input.pointer.f;
import androidx.compose.ui.input.pointer.g;
import androidx.compose.ui.input.pointer.v;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.InterfaceC0926w;
import androidx.compose.ui.node.l0;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class d extends AbstractC0918n implements InterfaceC0926w, l0, androidx.compose.ui.focus.d {
    public Function0 p;
    public boolean q;
    public final B r;

    public d(Function0 function0) {
        this.p = function0;
        c cVar = new c(this, null);
        f fVar = v.a;
        B b = new B(null, null, cVar);
        M0(b);
        this.r = b;
    }

    @Override // androidx.compose.ui.node.l0
    public final void E(f fVar, g gVar, long j) {
        this.r.E(fVar, gVar, j);
    }

    @Override // androidx.compose.ui.node.l0
    public final void F() {
        this.r.F();
    }

    @Override // androidx.compose.ui.focus.d
    public final void d0(s sVar) {
        this.q = sVar.a();
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final L h(M m, J j, long j2) {
        int iM0 = m.m0(a.a);
        int iM02 = m.m0(a.b);
        int i = iM02 * 2;
        int i2 = iM0 * 2;
        W wB = j.B(L5.o(i, i2, j2));
        return m.n0(wB.a - i, wB.b - i2, V.c(), new O0(wB, iM02, iM0, 2));
    }
}
