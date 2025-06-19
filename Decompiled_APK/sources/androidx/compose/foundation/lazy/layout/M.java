package androidx.compose.foundation.lazy.layout;

import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M {
    public final androidx.compose.runtime.saveable.c a;
    public final androidx.compose.foundation.lazy.j b;
    public final LinkedHashMap c = new LinkedHashMap();

    public M(androidx.compose.runtime.saveable.c cVar, androidx.compose.foundation.lazy.j jVar) {
        this.a = cVar;
        this.b = jVar;
    }

    public final Function2 a(int i, Object obj, Object obj2) {
        LinkedHashMap linkedHashMap = this.c;
        L l = (L) linkedHashMap.get(obj);
        if (l != null && l.c == i && Intrinsics.b(l.b, obj2)) {
            androidx.compose.runtime.internal.d dVar = l.d;
            if (dVar != null) {
                return dVar;
            }
            androidx.compose.runtime.internal.d dVar2 = new androidx.compose.runtime.internal.d(true, 1403994769, new androidx.compose.foundation.contextmenu.i(6, l.e, l));
            l.d = dVar2;
            return dVar2;
        }
        L l2 = new L(this, i, obj, obj2);
        linkedHashMap.put(obj, l2);
        androidx.compose.runtime.internal.d dVar3 = l2.d;
        if (dVar3 != null) {
            return dVar3;
        }
        androidx.compose.runtime.internal.d dVar4 = new androidx.compose.runtime.internal.d(true, 1403994769, new androidx.compose.foundation.contextmenu.i(6, this, l2));
        l2.d = dVar4;
        return dVar4;
    }

    public final Object b(Object obj) {
        if (obj == null) {
            return null;
        }
        L l = (L) this.c.get(obj);
        if (l != null) {
            return l.b;
        }
        N n = (N) this.b.invoke();
        int iA = n.a(obj);
        if (iA != -1) {
            return n.c(iA);
        }
        return null;
    }
}
