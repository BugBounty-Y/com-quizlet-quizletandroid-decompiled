package com.google.firebase.messaging;

import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class q {
    public static final com.google.android.gms.internal.appset.e a;

    static {
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        com.google.firebase.encoders.json.a aVar = com.google.firebase.encoders.proto.f.a;
        map.put(q.class, C3966c.a);
        map2.remove(q.class);
        map.put(com.google.firebase.messaging.reporting.e.class, C3965b.a);
        map2.remove(com.google.firebase.messaging.reporting.e.class);
        map.put(com.google.firebase.messaging.reporting.d.class, C3964a.a);
        map2.remove(com.google.firebase.messaging.reporting.d.class);
        a = new com.google.android.gms.internal.appset.e(new HashMap(map), new HashMap(map2), aVar, 9);
    }
}
