package com.snowplowanalytics.snowplow.network;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final com.snowplowanalytics.snowplow.payload.b a;
    public final ArrayList b;
    public final boolean c;
    public final String d;

    public h(com.snowplowanalytics.snowplow.payload.b payload, long j, boolean z) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        ArrayList arrayList = new ArrayList();
        arrayList.add(Long.valueOf(j));
        this.b = arrayList;
        this.a = payload;
        this.c = z;
        HashMap map = payload.b;
        String str = null;
        map = map == null ? null : map;
        if (map != null) {
            Object obj = map.get("ua");
            if (obj instanceof String) {
                str = (String) obj;
            }
        }
        this.d = str;
    }

    public h(ArrayList payloads, ArrayList emitterEventIds) {
        String str;
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        Intrinsics.checkNotNullParameter(emitterEventIds, "emitterEventIds");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = payloads.iterator();
        loop0: while (true) {
            str = null;
            while (it2.hasNext()) {
                com.snowplowanalytics.snowplow.payload.b bVar = (com.snowplowanalytics.snowplow.payload.b) it2.next();
                arrayList.add(bVar.b);
                HashMap map = bVar.b;
                if (map == null) {
                    map = null;
                }
                if (map != null) {
                    Object obj = map.get("ua");
                    str = obj instanceof String ? (String) obj : str;
                }
            }
            break loop0;
        }
        com.snowplowanalytics.snowplow.payload.b bVar2 = new com.snowplowanalytics.snowplow.payload.b();
        this.a = bVar2;
        HashMap map2 = new com.snowplowanalytics.snowplow.payload.a("iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4", arrayList).a;
        HashMap map3 = map2 != null ? map2 : null;
        if (map3 != null) {
            bVar2.c(map3);
        }
        this.b = emitterEventIds;
        this.d = str;
        this.c = false;
    }
}
