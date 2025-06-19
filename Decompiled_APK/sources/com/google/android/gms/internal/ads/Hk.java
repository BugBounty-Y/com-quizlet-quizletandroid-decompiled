package com.google.android.gms.internal.ads;

import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class Hk {
    public final Kk a;
    public final Xv b;
    public final HashMap c;

    public Hk(Kk kk, Xv xv) {
        this.a = kk;
        kk.getClass();
        this.c = new HashMap(kk.a);
        this.b = xv;
    }

    public final Fi a() {
        Fi fi = new Fi(this);
        ((ConcurrentHashMap) fi.b).putAll(this.c);
        return fi;
    }

    public final void b() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Db)).booleanValue()) {
            Fi fiA = a();
            fiA.o("action", "pecr");
            fiA.x();
        }
    }
}
