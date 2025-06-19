package androidx.compose.foundation;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.InterfaceC0919o;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class M extends androidx.compose.ui.p implements InterfaceC0919o {
    public final androidx.compose.foundation.interaction.k n;
    public boolean o;
    public boolean p;
    public boolean q;

    public M(androidx.compose.foundation.interaction.k kVar) {
        this.n = kVar;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        kotlinx.coroutines.E.A(A0(), null, null, new L(this, null), 3);
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(androidx.compose.ui.node.G g) {
        g.b();
        boolean z = this.o;
        androidx.compose.ui.graphics.drawscope.b bVar = g.a;
        if (z) {
            androidx.compose.ui.graphics.drawscope.d.I(g, C0861v.b(C0861v.b, 0.3f), 0L, bVar.g(), DefinitionKt.NO_Float_VALUE, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND);
        } else if (this.p || this.q) {
            androidx.compose.ui.graphics.drawscope.d.I(g, C0861v.b(C0861v.b, 0.1f), 0L, bVar.g(), DefinitionKt.NO_Float_VALUE, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND);
        }
    }
}
