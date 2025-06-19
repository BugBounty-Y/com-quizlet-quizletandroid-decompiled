package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;

/* loaded from: classes2.dex */
public final class Tp extends AbstractBinderC2814x5 {
    public final Qp a;
    public final Np b;
    public final C1893bq c;
    public C2105gk d;
    public boolean e;

    public Tp(Qp qp, Np np, C1893bq c1893bq) {
        super("com.google.android.gms.ads.internal.reward.client.IRewardedVideoAd");
        this.e = false;
        this.a = qp;
        this.b = np;
        this.c = c1893bq;
    }

    public final synchronized void H2(com.google.android.gms.dynamic.a aVar) {
        com.google.android.gms.common.internal.u.d("pause must be called on the main UI thread.");
        if (this.d != null) {
            Context context = aVar == null ? null : (Context) com.google.android.gms.dynamic.b.I3(aVar);
            C2403nh c2403nh = this.d.c;
            c2403nh.getClass();
            c2403nh.j1(new C2274kh(context));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:154:0x022a A[Catch: all -> 0x021e, TryCatch #6 {, blocks: (B:143:0x01ff, B:147:0x0217, B:153:0x0221, B:154:0x022a, B:156:0x0230, B:160:0x0244), top: B:178:0x01ff, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:158:0x0242 A[DONT_GENERATE] */
    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean d4(int r6, android.os.Parcel r7, android.os.Parcel r8) {
        /*
            Method dump skipped, instructions count: 654
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Tp.d4(int, android.os.Parcel, android.os.Parcel):boolean");
    }

    public final synchronized void e4(com.google.android.gms.dynamic.a aVar) {
        try {
            com.google.android.gms.common.internal.u.d("showAd must be called on the main UI thread.");
            if (this.d != null) {
                Activity activity = null;
                if (aVar != null) {
                    Object objI3 = com.google.android.gms.dynamic.b.I3(aVar);
                    if (objI3 instanceof Activity) {
                        activity = (Activity) objI3;
                    }
                }
                this.d.b(activity, this.e);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized boolean f4() {
        C2105gk c2105gk = this.d;
        if (c2105gk != null) {
            if (!c2105gk.p.b.get()) {
                return true;
            }
        }
        return false;
    }

    public final synchronized void t0(com.google.android.gms.dynamic.a aVar) {
        com.google.android.gms.common.internal.u.d("destroy must be called on the main UI thread.");
        Context context = null;
        this.b.b.set(null);
        if (this.d != null) {
            if (aVar != null) {
                context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
            }
            C2403nh c2403nh = this.d.c;
            c2403nh.getClass();
            c2403nh.j1(new C2360mh(context));
        }
    }

    public final synchronized void v2(com.google.android.gms.dynamic.a aVar) {
        com.google.android.gms.common.internal.u.d("resume must be called on the main UI thread.");
        if (this.d != null) {
            Context context = aVar == null ? null : (Context) com.google.android.gms.dynamic.b.I3(aVar);
            C2403nh c2403nh = this.d.c;
            c2403nh.getClass();
            c2403nh.j1(new C2317lh(context));
        }
    }
}
