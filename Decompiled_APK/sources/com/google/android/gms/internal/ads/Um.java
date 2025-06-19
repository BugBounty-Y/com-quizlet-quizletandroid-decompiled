package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Um implements InterfaceC2751vm {
    public final Context b;
    public final C2406nk c;
    public final C2023eq d;
    public final Executor e;
    public final VersionInfoParcel f;
    public final C2475p9 g;
    public final BinderC2408nm i;
    public final Ek j;
    public final Hk k;
    public final Object l;
    public final /* synthetic */ int a = 0;
    public final boolean h = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T8)).booleanValue();

    public Um(Context context, VersionInfoParcel versionInfoParcel, C2023eq c2023eq, Executor executor, C1813Ze c1813Ze, C2406nk c2406nk, C2475p9 c2475p9, BinderC2408nm binderC2408nm, Ek ek, Hk hk) {
        this.b = context;
        this.d = c2023eq;
        this.l = c1813Ze;
        this.e = executor;
        this.f = versionInfoParcel;
        this.c = c2406nk;
        this.g = c2475p9;
        this.i = binderC2408nm;
        this.j = ek;
        this.k = hk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        switch (this.a) {
            case 0:
                Yp yp = vp.s;
                if (yp == null || yp.a == null) {
                }
                break;
            default:
                Yp yp2 = vp.s;
                if (yp2 == null || yp2.a == null) {
                }
                break;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        switch (this.a) {
            case 0:
                C2147hi c2147hi = new C2147hi(12, (byte) 0);
                Tv tv = Tv.b;
                C2616sg c2616sg = new C2616sg(this, vp, c1849aq, c2147hi, 7);
                Executor executor = this.e;
                C2846xv c2846xvN = AbstractC2025es.N(tv, c2616sg, executor);
                c2846xvN.a(new C4(c2147hi, 4), executor);
                return c2846xvN;
            default:
                C2147hi c2147hi2 = new C2147hi(12, (byte) 0);
                Tv tv2 = Tv.b;
                C2616sg c2616sg2 = new C2616sg(this, vp, c1849aq, c2147hi2, 9);
                Executor executor2 = this.e;
                C2846xv c2846xvN2 = AbstractC2025es.N(tv2, c2616sg2, executor2);
                c2846xvN2.a(new C4(c2147hi2, 5), executor2);
                return c2846xvN2;
        }
    }

    public Um(Context context, VersionInfoParcel versionInfoParcel, C2023eq c2023eq, Executor executor, C1882bf c1882bf, C2406nk c2406nk, C2475p9 c2475p9, BinderC2408nm binderC2408nm, Ek ek, Hk hk) {
        this.b = context;
        this.d = c2023eq;
        this.l = c1882bf;
        this.e = executor;
        this.f = versionInfoParcel;
        this.c = c2406nk;
        this.g = c2475p9;
        this.i = binderC2408nm;
        this.j = ek;
        this.k = hk;
    }
}
