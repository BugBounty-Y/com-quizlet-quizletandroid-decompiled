package androidx.compose.ui.focus;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends androidx.compose.ui.p implements d {
    public Function1 n;
    public s o;

    @Override // androidx.compose.ui.focus.d
    public final void d0(s sVar) {
        if (Intrinsics.b(this.o, sVar)) {
            return;
        }
        this.o = sVar;
        this.n.invoke(sVar);
    }
}
