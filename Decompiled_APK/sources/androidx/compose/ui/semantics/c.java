package androidx.compose.ui.semantics;

import androidx.compose.ui.node.n0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class c extends androidx.compose.ui.p implements n0 {
    public boolean n;
    public final boolean o;
    public Function1 p;

    public c(boolean z, boolean z2, Function1 function1) {
        this.n = z;
        this.o = z2;
        this.p = function1;
    }

    @Override // androidx.compose.ui.node.n0
    public final boolean G() {
        return this.o;
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(v vVar) {
        this.p.invoke(vVar);
    }

    @Override // androidx.compose.ui.node.n0
    public final boolean x0() {
        return this.n;
    }
}
