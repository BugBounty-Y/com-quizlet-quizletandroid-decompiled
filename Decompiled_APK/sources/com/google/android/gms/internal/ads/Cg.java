package com.google.android.gms.internal.ads;

import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class Cg implements Wh, InterfaceC2617sh {
    public final com.google.android.gms.common.util.a a;
    public final Dg b;
    public final C2023eq c;
    public final String d;

    public Cg(com.google.android.gms.common.util.a aVar, Dg dg, C2023eq c2023eq, String str) {
        this.a = aVar;
        this.b = dg;
        this.c = c2023eq;
        this.d = str;
    }

    @Override // com.google.android.gms.internal.ads.Wh
    public final void a() {
        this.b.c.put(this.d, Long.valueOf(this.a.elapsedRealtime()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        long jElapsedRealtime = this.a.elapsedRealtime();
        String str = this.c.f;
        Dg dg = this.b;
        ConcurrentHashMap concurrentHashMap = dg.c;
        String str2 = this.d;
        Long l = (Long) concurrentHashMap.get(str2);
        if (l == null) {
            return;
        }
        concurrentHashMap.remove(str2);
        dg.d.put(str, Long.valueOf(jElapsedRealtime - l.longValue()));
    }
}
