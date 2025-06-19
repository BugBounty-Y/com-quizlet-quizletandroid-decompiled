package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Mk {
    public final String e;
    public final Kk f;
    public final ArrayList b = new ArrayList();
    public boolean c = false;
    public boolean d = false;
    public final com.google.android.gms.ads.internal.util.C a = com.google.android.gms.ads.internal.j.C.h.d();

    public Mk(String str, Kk kk) {
        this.e = str;
        this.f = kk;
    }

    public final synchronized void a(String str, String str2) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c2)).booleanValue()) {
            HashMap mapE = e();
            mapE.put("action", "adapter_init_finished");
            mapE.put("ancn", str);
            mapE.put("rqe", str2);
            this.b.add(mapE);
        }
    }

    public final synchronized void b(String str) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c2)).booleanValue()) {
            HashMap mapE = e();
            mapE.put("action", "adapter_init_started");
            mapE.put("ancn", str);
            this.b.add(mapE);
        }
    }

    public final synchronized void c(String str) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c2)).booleanValue()) {
            HashMap mapE = e();
            mapE.put("action", "adapter_init_finished");
            mapE.put("ancn", str);
            this.b.add(mapE);
        }
    }

    public final synchronized void d() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c2)).booleanValue() && !this.c) {
            HashMap mapE = e();
            mapE.put("action", "init_started");
            this.b.add(mapE);
            this.c = true;
        }
    }

    public final HashMap e() {
        Kk kk = this.f;
        kk.getClass();
        HashMap map = new HashMap(kk.a);
        com.google.android.gms.ads.internal.j.C.k.getClass();
        map.put("tms", Long.toString(SystemClock.elapsedRealtime(), 10));
        map.put("tid", this.a.k() ? "" : this.e);
        return map;
    }
}
