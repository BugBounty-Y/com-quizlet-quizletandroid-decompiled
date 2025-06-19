package androidx.compose.ui.draw;

import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.p;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class h extends p implements InterfaceC0919o {
    public Function1 n;

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) {
        this.n.invoke(g);
    }
}
