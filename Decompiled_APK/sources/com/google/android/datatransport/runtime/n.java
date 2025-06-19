package com.google.android.datatransport.runtime;

import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class n {
    public static final com.google.android.gms.internal.appset.e a;

    static {
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        com.google.firebase.encoders.json.a aVar = com.google.firebase.encoders.proto.f.a;
        map.put(n.class, e.a);
        map2.remove(n.class);
        map.put(com.google.android.datatransport.runtime.firebase.transport.a.class, a.a);
        map2.remove(com.google.android.datatransport.runtime.firebase.transport.a.class);
        map.put(com.google.android.datatransport.runtime.firebase.transport.g.class, g.a);
        map2.remove(com.google.android.datatransport.runtime.firebase.transport.g.class);
        map.put(com.google.android.datatransport.runtime.firebase.transport.e.class, d.a);
        map2.remove(com.google.android.datatransport.runtime.firebase.transport.e.class);
        map.put(com.google.android.datatransport.runtime.firebase.transport.d.class, c.a);
        map2.remove(com.google.android.datatransport.runtime.firebase.transport.d.class);
        map.put(com.google.android.datatransport.runtime.firebase.transport.b.class, b.a);
        map2.remove(com.google.android.datatransport.runtime.firebase.transport.b.class);
        map.put(com.google.android.datatransport.runtime.firebase.transport.f.class, f.a);
        map2.remove(com.google.android.datatransport.runtime.firebase.transport.f.class);
        a = new com.google.android.gms.internal.appset.e(new HashMap(map), new HashMap(map2), aVar, 9);
    }
}
