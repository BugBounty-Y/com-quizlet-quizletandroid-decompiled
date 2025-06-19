package com.google.android.gms.internal.ads;

import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.Rd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC1764Rd implements Runnable {
    public final /* synthetic */ String a;
    public final /* synthetic */ String b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ long f;
    public final /* synthetic */ long g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ AbstractC1794Wd k;

    public RunnableC1764Rd(AbstractC1794Wd abstractC1794Wd, String str, String str2, long j, long j2, long j3, long j4, long j5, boolean z, int i, int i2) {
        this.a = str;
        this.b = str2;
        this.c = j;
        this.d = j2;
        this.e = j3;
        this.f = j4;
        this.g = j5;
        this.h = z;
        this.i = i;
        this.j = i2;
        this.k = abstractC1794Wd;
    }

    @Override // java.lang.Runnable
    public final void run() {
        HashMap map = new HashMap();
        map.put("event", "precacheProgress");
        map.put("src", this.a);
        map.put("cachedSrc", this.b);
        map.put("bufferedDuration", Long.toString(this.c));
        map.put("totalDuration", Long.toString(this.d));
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue()) {
            map.put("qoeLoadedBytes", Long.toString(this.e));
            map.put("qoeCachedBytes", Long.toString(this.f));
            map.put("totalBytes", Long.toString(this.g));
            com.google.android.gms.ads.internal.j.C.k.getClass();
            map.put("reportTime", Long.toString(System.currentTimeMillis()));
        }
        map.put("cacheReady", true != this.h ? "0" : "1");
        map.put("playerCount", Integer.toString(this.i));
        map.put("playerPreparedCount", Integer.toString(this.j));
        AbstractC1794Wd.k(this.k, map);
    }
}
