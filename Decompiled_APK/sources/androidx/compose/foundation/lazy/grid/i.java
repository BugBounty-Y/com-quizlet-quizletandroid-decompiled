package androidx.compose.foundation.lazy.grid;

import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.layout.H;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class i extends AbstractC0448u {
    public final x b = new x(this);
    public final C0122z c = new C0122z(1, (byte) 0);
    public boolean d;

    public i(Function1 function1) {
        function1.invoke(this);
    }

    public static void o(i iVar, Function1 function1, androidx.compose.runtime.internal.d dVar) {
        iVar.getClass();
        iVar.c.c(1, new f(null, new h(0, function1), new o(1, 4), new androidx.compose.runtime.internal.d(true, -34608120, new H(dVar, 1))));
        iVar.d = true;
    }

    public static /* synthetic */ void q(i iVar, int i, androidx.paging.compose.a aVar, Function2 function2, androidx.compose.runtime.internal.d dVar, int i2) {
        if ((i2 & 2) != 0) {
            aVar = null;
        }
        if ((i2 & 4) != 0) {
            function2 = null;
        }
        iVar.p(i, aVar, function2, o.c, dVar);
    }

    @Override // androidx.compose.foundation.lazy.layout.AbstractC0448u
    public final C0122z j() {
        return this.c;
    }

    public final void p(int i, Function1 function1, Function2 function2, Function1 function12, androidx.compose.runtime.internal.d dVar) {
        this.c.c(i, new f(function1, function2 == null ? g.b : function2, function12, dVar));
        if (function2 != null) {
            this.d = true;
        }
    }
}
