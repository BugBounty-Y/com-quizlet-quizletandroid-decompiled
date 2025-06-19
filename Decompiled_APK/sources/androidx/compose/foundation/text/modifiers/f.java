package androidx.compose.foundation.text.modifiers;

import androidx.compose.foundation.text.selection.C0541w;
import androidx.compose.foundation.text.selection.b0;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.InterfaceC0920p;
import androidx.compose.ui.node.InterfaceC0926w;
import androidx.compose.ui.node.O;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.L;
import java.util.List;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class f extends AbstractC0918n implements InterfaceC0926w, InterfaceC0919o, InterfaceC0920p {
    public h p;
    public final m q;

    public f(C0995g c0995g, L l, androidx.compose.ui.text.font.i iVar, Function1 function1, int i, boolean z, int i2, int i3, List list, Function1 function12, h hVar) {
        this.p = hVar;
        m mVar = new m(c0995g, l, iVar, function1, i, z, i2, i3, list, function12, hVar, null);
        M0(mVar);
        this.q = mVar;
        if (this.p == null) {
            throw new IllegalArgumentException("Do not use SelectionCapableStaticTextModifier unless selectionController != null");
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(O o, J j, int i) {
        return this.q.b(o, j, i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(O o, J j, int i) {
        return this.q.c(o, j, i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) throws Throwable {
        this.q.e(g);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(O o, J j, int i) {
        return this.q.f(o, j, i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(M m, J j, long j2) {
        return this.q.h(m, j, j2);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(O o, J j, int i) {
        return this.q.i(o, j, i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0920p
    public final void y0(a0 a0Var) {
        h hVar = this.p;
        if (hVar != null) {
            hVar.d = j.a(hVar.d, a0Var, null, 2);
            b0 b0Var = (b0) hVar.b;
            b0Var.a = false;
            C0541w c0541w = b0Var.e;
            if (c0541w != null) {
                c0541w.invoke(Long.valueOf(hVar.a));
            }
        }
    }
}
