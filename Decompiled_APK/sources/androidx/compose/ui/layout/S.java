package androidx.compose.ui.layout;

import androidx.compose.ui.node.InterfaceC0925v;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class S extends androidx.compose.ui.p implements InterfaceC0925v {
    public Function1 n;
    public long o;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return true;
    }

    @Override // androidx.compose.ui.node.InterfaceC0925v
    public final void o(long j) {
        if (androidx.compose.ui.unit.j.a(this.o, j)) {
            return;
        }
        this.n.invoke(new androidx.compose.ui.unit.j(j));
        this.o = j;
    }
}
