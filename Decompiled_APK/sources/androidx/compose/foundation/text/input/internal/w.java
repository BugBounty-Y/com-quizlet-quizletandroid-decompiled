package androidx.compose.foundation.text.input.internal;

import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.InterfaceC0920p;
import androidx.compose.ui.node.a0;

/* loaded from: classes.dex */
public final class w extends androidx.compose.ui.p implements InterfaceC0916l, InterfaceC0920p, InterfaceC0917m {
    public g n;
    public C0492h0 o;
    public i0 p;
    public final InterfaceC0773a0 q = C0776c.z(null);

    public w(g gVar, C0492h0 c0492h0, i0 i0Var) {
        this.n = gVar;
        this.o = c0492h0;
        this.p = i0Var;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        g gVar = this.n;
        if (gVar.a != null) {
            throw new IllegalStateException("Expected textInputModifierNode to be null");
        }
        gVar.a = this;
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        this.n.k(this);
    }

    @Override // androidx.compose.ui.node.InterfaceC0920p
    public final void y0(a0 a0Var) {
        ((L0) this.q).setValue(a0Var);
    }
}
