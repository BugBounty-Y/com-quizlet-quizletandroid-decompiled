package com.google.android.gms.internal.ads;

import java.io.Serializable;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.xu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2845xu extends Ut implements Serializable {
    public final transient Map d;
    public transient int e;
    public final transient Ft f;

    public C2845xu(Map map, Ft ft) {
        AbstractC1981ds.C(map.isEmpty());
        this.d = map;
        this.f = ft;
    }

    public final void b() {
        Map map = this.d;
        Iterator it2 = map.values().iterator();
        while (it2.hasNext()) {
            ((Collection) it2.next()).clear();
        }
        map.clear();
        this.e = 0;
    }
}
