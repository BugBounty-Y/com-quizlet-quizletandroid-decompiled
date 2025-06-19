package androidx.lifecycle;

import java.util.Iterator;
import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class B0 {
    public final LinkedHashMap a = new LinkedHashMap();

    public final void a() {
        LinkedHashMap linkedHashMap = this.a;
        Iterator it2 = linkedHashMap.values().iterator();
        while (it2.hasNext()) {
            ((w0) it2.next()).x();
        }
        linkedHashMap.clear();
    }
}
