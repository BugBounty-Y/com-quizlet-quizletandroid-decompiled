package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Binder;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.AbstractCollection;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Uq implements Runnable {
    public static final Object i = new Object();
    public static final Object j = new Object();
    public static final Object k = new Object();
    public static Boolean l;
    public final Context a;
    public final VersionInfoParcel b;
    public int e;
    public final C2620sk f;
    public final AbstractCollection g;
    public final Xq c = C1850ar.x();
    public String d = "";
    public boolean h = false;

    public Uq(Context context, VersionInfoParcel versionInfoParcel, C2620sk c2620sk, L9 l9) {
        this.a = context;
        this.b = versionInfoParcel;
        this.f = c2620sk;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Q8)).booleanValue()) {
            this.g = com.google.android.gms.ads.internal.util.F.z();
        } else {
            C2244ju c2244ju = AbstractC2330lu.b;
            this.g = Bu.e;
        }
    }

    public static boolean a() {
        boolean zBooleanValue;
        synchronized (i) {
            try {
                if (l == null) {
                    if (((Boolean) R7.b.o()).booleanValue()) {
                        l = Boolean.valueOf(Math.random() < ((Double) R7.a.o()).doubleValue());
                    } else {
                        l = Boolean.FALSE;
                    }
                }
                zBooleanValue = l.booleanValue();
            } catch (Throwable th) {
                throw th;
            }
        }
        return zBooleanValue;
    }

    public final void b(Rq rq) {
        AbstractC2270kd.a.a(new RunnableC2793wl(12, this, rq));
    }

    @Override // java.lang.Runnable
    public final void run() {
        byte[] bArrD;
        if (a()) {
            Object obj = j;
            synchronized (obj) {
                try {
                    if (((C1850ar) this.c.b).w() == 0) {
                        return;
                    }
                    try {
                        synchronized (obj) {
                            Xq xq = this.c;
                            bArrD = ((C1850ar) xq.c()).d();
                            xq.e();
                            C1850ar.z((C1850ar) xq.b);
                        }
                        Ul ul = new Ul((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K8), 60000, new HashMap(), bArrD, "application/x-protobuf");
                        Context context = this.a;
                        String str = this.b.a;
                        Binder.getCallingUid();
                        new C1732Mb(25, context, str).j(ul);
                    } catch (Exception e) {
                        if ((e instanceof zzdwf) && ((zzdwf) e).a == 3) {
                            return;
                        }
                        com.google.android.gms.ads.internal.j.C.h.g("CuiMonitor.sendCuiPing", e);
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }
}
