package androidx.navigation.compose;

import androidx.navigation.C1291m;
import androidx.navigation.V;
import androidx.navigation.W;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

@V("dialog")
@Metadata
/* loaded from: classes.dex */
public final class s extends W {
    public s() {
        Intrinsics.checkNotNullParameter("dialog", "name");
    }

    @Override // androidx.navigation.W
    public final androidx.navigation.B a() {
        return new r(this, new androidx.compose.ui.window.r(7), AbstractC1272e.a);
    }

    @Override // androidx.navigation.W
    public final void d(List list, androidx.navigation.K k) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            b().f((C1291m) it2.next());
        }
    }

    @Override // androidx.navigation.W
    public final void f(C1291m c1291m, boolean z) {
        b().e(c1291m, z);
        int iP = CollectionsKt.P((Iterable) ((s0) b().f.a).getValue(), c1291m);
        int i = 0;
        for (Object obj : (Iterable) ((s0) b().f.a).getValue()) {
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            C1291m c1291m2 = (C1291m) obj;
            if (i > iP) {
                b().c(c1291m2);
            }
            i = i2;
        }
    }
}
