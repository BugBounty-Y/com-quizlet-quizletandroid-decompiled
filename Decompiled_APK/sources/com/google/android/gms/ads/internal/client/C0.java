package com.google.android.gms.ads.internal.client;

import android.app.Activity;
import android.os.RemoteException;
import com.google.android.gms.internal.ads.C2610sa;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.Qv;
import com.google.android.gms.internal.ads.zzblu;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class C0 {
    public static C0 h;
    public InterfaceC1585b0 f;
    public final Object a = new Object();
    public boolean c = false;
    public boolean d = false;
    public final Object e = new Object();
    public com.google.android.gms.ads.p g = new com.google.android.gms.ads.p(-1, -1, null, new ArrayList());
    public final ArrayList b = new ArrayList();

    static {
        new HashSet(Arrays.asList(com.google.android.gms.ads.c.APP_OPEN_AD, com.google.android.gms.ads.c.INTERSTITIAL, com.google.android.gms.ads.c.REWARDED));
    }

    public static L9 a(List list) {
        HashMap map = new HashMap();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            map.put(((zzblu) it2.next()).a, new L9(0));
        }
        return new L9(1);
    }

    public static C0 e() {
        C0 c0;
        synchronized (C0.class) {
            try {
                if (h == null) {
                    h = new C0();
                }
                c0 = h;
            } catch (Throwable th) {
                throw th;
            }
        }
        return c0;
    }

    public final void b(Activity activity) {
        try {
            if (C2610sa.b == null) {
                C2610sa.b = new C2610sa(0);
            }
            Object obj = null;
            if (C2610sa.b.a.compareAndSet(false, true)) {
                new Thread(new Qv(8, activity, obj)).start();
            }
            this.f.t();
            this.f.q3(new com.google.android.gms.dynamic.b(null), null);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("MobileAdsSettingManager initialization failed", e);
        }
    }

    public final void c(Activity activity) {
        if (this.f == null) {
            this.f = (InterfaceC1585b0) new C1604l(C1614q.f.b, activity).d(activity, false);
        }
    }

    public final com.google.android.gms.ads.initialization.a d() {
        L9 l9A;
        synchronized (this.e) {
            try {
                com.google.android.gms.common.internal.u.j("MobileAds.initialize() must be called prior to getting initialization status.", this.f != null);
                try {
                    l9A = a(this.f.h());
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.client.i.e("Unable to get Initialization status.");
                    return new R0();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return l9A;
    }
}
