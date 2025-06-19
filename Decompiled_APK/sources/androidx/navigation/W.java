package androidx.navigation;

import java.util.List;
import java.util.ListIterator;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public abstract class W {
    public C1295q a;
    public boolean b;

    public abstract B a();

    public final C1295q b() {
        C1295q c1295q = this.a;
        if (c1295q != null) {
            return c1295q;
        }
        throw new IllegalStateException("You cannot access the Navigator's state until the Navigator is attached");
    }

    public B c(B destination) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        return destination;
    }

    public void d(List entries, K k) {
        Intrinsics.checkNotNullParameter(entries, "entries");
        kotlin.sequences.e eVar = new kotlin.sequences.e(kotlin.sequences.q.f(kotlin.sequences.q.h(CollectionsKt.D(entries), new U(0, this, k))));
        while (eVar.hasNext()) {
            b().f((C1291m) eVar.next());
        }
    }

    public void e(C1295q state) {
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = state;
        this.b = true;
    }

    public void f(C1291m popUpTo, boolean z) {
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        List list = (List) ((s0) b().e.a).getValue();
        if (!list.contains(popUpTo)) {
            throw new IllegalStateException(("popBackStack was called with " + popUpTo + " which does not exist in back stack " + list).toString());
        }
        ListIterator listIterator = list.listIterator(list.size());
        C1291m c1291m = null;
        while (g()) {
            c1291m = (C1291m) listIterator.previous();
            if (Intrinsics.b(c1291m, popUpTo)) {
                break;
            }
        }
        if (c1291m != null) {
            b().d(c1291m, z);
        }
    }

    public boolean g() {
        return true;
    }
}
