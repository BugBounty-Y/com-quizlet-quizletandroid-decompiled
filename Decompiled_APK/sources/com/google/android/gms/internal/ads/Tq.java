package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import com.amazon.device.ads.DTBAdSize;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class Tq implements Runnable {
    public final Uq b;
    public String c;
    public String e;
    public androidx.work.impl.model.n f;
    public zze g;
    public ScheduledFuture h;
    public final ArrayList a = new ArrayList();
    public int i = 2;
    public int d = 2;

    public Tq(Uq uq) {
        this.b = uq;
    }

    public final synchronized void a(Pq pq) {
        try {
            if (((Boolean) R7.c.o()).booleanValue()) {
                ArrayList arrayList = this.a;
                pq.i();
                arrayList.add(pq);
                ScheduledFuture scheduledFuture = this.h;
                if (scheduledFuture != null) {
                    scheduledFuture.cancel(false);
                }
                this.h = AbstractC2270kd.d.schedule(this, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.N8)).intValue(), TimeUnit.MILLISECONDS);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void b(String str) {
        boolean zMatches;
        if (((Boolean) R7.c.o()).booleanValue()) {
            if (TextUtils.isEmpty(str)) {
                zMatches = false;
            } else {
                zMatches = Pattern.matches((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.O8), str);
            }
            if (zMatches) {
                this.c = str;
            }
        }
    }

    public final synchronized void c(zze zzeVar) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            this.g = zzeVar;
        }
    }

    public final synchronized void d(ArrayList arrayList) {
        try {
            if (((Boolean) R7.c.o()).booleanValue()) {
                if (arrayList.contains(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER) || arrayList.contains("BANNER")) {
                    this.i = 3;
                } else if (arrayList.contains(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE) || arrayList.contains("INTERSTITIAL")) {
                    this.i = 4;
                } else if (arrayList.contains(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE) || arrayList.contains("NATIVE")) {
                    this.i = 8;
                } else if (arrayList.contains("rewarded") || arrayList.contains("REWARDED")) {
                    this.i = 5;
                } else if (arrayList.contains("app_open_ad")) {
                    this.i = 7;
                } else if (arrayList.contains("rewarded_interstitial") || arrayList.contains("REWARDED_INTERSTITIAL")) {
                    this.i = 6;
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void e(String str) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            this.e = str;
        }
    }

    public final synchronized void f(Bundle bundle) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            this.d = AbstractC3429b3.c(bundle);
        }
    }

    public final synchronized void g(androidx.work.impl.model.n nVar) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            this.f = nVar;
        }
    }

    public final synchronized void h() {
        try {
            if (((Boolean) R7.c.o()).booleanValue()) {
                ScheduledFuture scheduledFuture = this.h;
                if (scheduledFuture != null) {
                    scheduledFuture.cancel(false);
                }
                ArrayList arrayList = this.a;
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    Pq pq = (Pq) it2.next();
                    int i = this.i;
                    if (i != 2) {
                        pq.e(i);
                    }
                    if (!TextUtils.isEmpty(this.c)) {
                        pq.R(this.c);
                    }
                    if (!TextUtils.isEmpty(this.e) && !pq.k()) {
                        pq.I(this.e);
                    }
                    androidx.work.impl.model.n nVar = this.f;
                    if (nVar != null) {
                        pq.f(nVar);
                    } else {
                        zze zzeVar = this.g;
                        if (zzeVar != null) {
                            pq.j(zzeVar);
                        }
                    }
                    pq.d(this.d);
                    this.b.b(pq.l());
                }
                arrayList.clear();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void i(int i) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            this.i = i;
        }
    }

    @Override // java.lang.Runnable
    public final synchronized void run() {
        h();
    }
}
