package androidx.compose.foundation.pager;

import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class t extends AbstractC0448u {
    public final Function1 b;
    public final C0122z c;

    public t(kotlin.jvm.functions.d dVar, Function1 function1, int i) {
        this.b = function1;
        C0122z c0122z = new C0122z(1, (byte) 0);
        c0122z.c(i, new o(function1, dVar));
        this.c = c0122z;
    }

    @Override // androidx.compose.foundation.lazy.layout.AbstractC0448u
    public final C0122z j() {
        return this.c;
    }
}
