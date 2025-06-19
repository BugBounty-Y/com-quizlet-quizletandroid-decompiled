package androidx.compose.foundation;

import androidx.compose.animation.C0278e;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class T extends androidx.compose.ui.p {
    public androidx.compose.foundation.interaction.l n;
    public androidx.compose.foundation.interaction.d o;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    public final void M0(androidx.compose.foundation.interaction.l lVar, androidx.compose.foundation.interaction.j jVar) {
        if (!this.m) {
            lVar.a(jVar);
            return;
        }
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) ((kotlinx.coroutines.internal.d) A0()).a.get(C5023i0.a);
        kotlinx.coroutines.E.A(A0(), null, null, new S(lVar, jVar, interfaceC5025j0 != null ? interfaceC5025j0.Q(new C0278e(9, lVar, jVar)) : null, null), 3);
    }
}
