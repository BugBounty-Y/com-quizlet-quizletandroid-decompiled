package com.google.android.gms.internal.ads;

import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final /* synthetic */ class Fk implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Fi b;

    public /* synthetic */ Fk(Fi fi, int i) {
        this.a = i;
        this.b = fi;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Fi fi = this.b;
                ((Hk) fi.c).a.b((ConcurrentHashMap) fi.b, false);
                break;
            case 1:
                Fi fi2 = this.b;
                ((Hk) fi2.c).a.b((ConcurrentHashMap) fi2.b, true);
                break;
            default:
                Fi fi3 = this.b;
                Kk kk = ((Hk) fi3.c).a;
                ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) fi3.b;
                kk.getClass();
                if (!concurrentHashMap.isEmpty()) {
                    kk.a(concurrentHashMap);
                    String strA = kk.f.a(concurrentHashMap);
                    com.google.android.gms.ads.internal.util.A.l(strA);
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.cd)).booleanValue() || kk.e) {
                        kk.c.execute(new Lk(kk, strA, 1));
                        break;
                    }
                } else {
                    com.google.android.gms.ads.internal.util.client.i.d("Empty paramMap.");
                    break;
                }
                break;
        }
    }
}
