package androidx.compose.ui;

import androidx.compose.foundation.text.selection.n0;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.node.InterfaceC0926w;
import kotlin.collections.V;

/* loaded from: classes.dex */
public final class u extends p implements InterfaceC0926w {
    public float n;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final L h(M m, J j, long j2) {
        W wB = j.B(j2);
        return m.n0(wB.a, wB.b, V.c(), new n0(15, wB, this));
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("ZIndexModifier(zIndex="), this.n, ')');
    }
}
