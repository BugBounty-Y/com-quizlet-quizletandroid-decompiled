package androidx.compose.foundation.layout;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E implements androidx.compose.ui.modifier.c {
    public final Function1 b;
    public R0 c;

    public E(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof E) && ((E) obj).b == this.b;
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.modifier.c
    public final void j(androidx.compose.ui.modifier.g gVar) {
        R0 r0 = (R0) gVar.d(U0.a);
        if (Intrinsics.b(r0, this.c)) {
            return;
        }
        this.c = r0;
        this.b.invoke(r0);
    }
}
