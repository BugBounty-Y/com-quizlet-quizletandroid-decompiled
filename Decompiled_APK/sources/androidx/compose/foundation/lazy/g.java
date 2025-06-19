package androidx.compose.foundation.lazy;

import androidx.appcompat.widget.C0122z;
import androidx.compose.animation.C0280g;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import java.util.ArrayList;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class g extends AbstractC0448u {
    public final C0122z b = new C0122z(1, (byte) 0);
    public ArrayList c;

    public g(Function1 function1) {
        function1.invoke(this);
    }

    public static /* synthetic */ void p(g gVar, Object obj, kotlin.jvm.functions.c cVar, int i) {
        if ((i & 1) != 0) {
            obj = null;
        }
        gVar.o(obj, cVar);
    }

    public static void s(g gVar, androidx.compose.runtime.internal.d dVar) {
        ArrayList arrayList = gVar.c;
        if (arrayList == null) {
            arrayList = new ArrayList();
            gVar.c = arrayList;
        }
        arrayList.add(Integer.valueOf(gVar.b.b));
        gVar.o(null, dVar);
    }

    @Override // androidx.compose.foundation.lazy.layout.AbstractC0448u
    public final C0122z j() {
        return this.b;
    }

    public final void o(Object obj, kotlin.jvm.functions.c cVar) {
        this.b.c(1, new C0425e(obj != null ? new C0280g(obj, 1) : null, new o(1, 3), new androidx.compose.runtime.internal.d(true, -1010194746, new f(cVar, 0))));
    }

    public final void q(int i, Function1 function1, Function1 function12, androidx.compose.runtime.internal.d dVar) {
        this.b.c(i, new C0425e(function1, function12, dVar));
    }
}
