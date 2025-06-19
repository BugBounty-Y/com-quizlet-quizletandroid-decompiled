package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class EC extends AC {
    public static final /* synthetic */ int b = 0;

    static {
        DC.a(Collections.EMPTY_MAP);
    }

    @Override // com.google.android.gms.internal.ads.HC
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final Map zzb() {
        Map map = this.a;
        LinkedHashMap linkedHashMapO = AbstractC2543qs.o(map.size());
        for (Map.Entry entry : map.entrySet()) {
            linkedHashMapO.put(entry.getKey(), ((HC) entry.getValue()).zzb());
        }
        return Collections.unmodifiableMap(linkedHashMapO);
    }
}
