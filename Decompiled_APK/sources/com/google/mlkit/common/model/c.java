package com.google.mlkit.common.model;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public final class c {
    public final HashMap a = new HashMap();

    public c(Set set) {
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            b bVar = (b) it2.next();
            HashMap map = this.a;
            bVar.getClass();
            map.put(a.class, bVar.a);
        }
    }

    public c() {
    }
}
