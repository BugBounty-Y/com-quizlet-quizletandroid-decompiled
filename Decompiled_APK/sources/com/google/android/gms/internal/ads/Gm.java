package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Gm implements Am {
    public final /* synthetic */ int a;
    public final Context b;
    public final Object c;
    public final Executor d;

    public /* synthetic */ Gm(Context context, Object obj, Executor executor, int i) {
        this.a = i;
        this.b = context;
        this.c = obj;
        this.d = executor;
    }

    /* JADX WARN: Removed duplicated region for block: B:89:0x052d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.lang.Object c(com.google.android.gms.internal.ads.C1849aq r63, com.google.android.gms.internal.ads.Vp r64, com.google.android.gms.internal.ads.C2880ym r65) throws com.google.android.gms.internal.ads.zzegy {
        /*
            Method dump skipped, instructions count: 3004
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Gm.c(com.google.android.gms.internal.ads.aq, com.google.android.gms.internal.ads.Vp, com.google.android.gms.internal.ads.ym):java.lang.Object");
    }

    public static final boolean d(C1849aq c1849aq, int i) {
        return ((C2023eq) c1849aq.a.b).g.contains(Integer.toString(i));
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final void a(C1849aq c1849aq, Vp vp, C2880ym c2880ym) throws JSONException, IOException {
        zzfcw zzfcwVar;
        com.google.android.gms.ads.internal.client.zzr zzrVarE;
        switch (this.a) {
            case 0:
                C2369mq c2369mq = (C2369mq) c2880ym.b;
                C2023eq c2023eq = (C2023eq) c1849aq.a.b;
                String string = vp.v.toString();
                Context context = this.b;
                InterfaceC1671Ca interfaceC1671Ca = (InterfaceC1671Ca) c2880ym.c;
                try {
                    c2369mq.a.n2(new com.google.android.gms.dynamic.b(context), c2023eq.d, string, interfaceC1671Ca);
                    return;
                } finally {
                }
            case 1:
                C2023eq c2023eq2 = (C2023eq) c1849aq.a.b;
                com.google.android.gms.ads.internal.client.zzr zzrVar = c2023eq2.e;
                boolean z = zzrVar.n;
                boolean z2 = vp.g0;
                Context context2 = this.b;
                int i = zzrVar.b;
                int i2 = zzrVar.e;
                if (z) {
                    com.google.android.gms.ads.h hVar = new com.google.android.gms.ads.h(i2, i);
                    hVar.e = true;
                    hVar.f = i;
                    zzrVarE = new com.google.android.gms.ads.internal.client.zzr(context2, hVar);
                } else {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S7)).booleanValue() && z2) {
                        com.google.android.gms.ads.h hVar2 = new com.google.android.gms.ads.h(i2, i);
                        hVar2.g = true;
                        hVar2.h = i;
                        zzrVarE = new com.google.android.gms.ads.internal.client.zzr(context2, hVar2);
                    } else {
                        zzrVarE = LA.e(context2, vp.u);
                    }
                }
                com.google.android.gms.ads.internal.client.zzr zzrVar2 = zzrVarE;
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S7)).booleanValue();
                Yp yp = vp.s;
                JSONObject jSONObject = vp.v;
                IInterface iInterface = c2880ym.c;
                Object obj = c2880ym.b;
                if (zBooleanValue && z2) {
                    C2369mq c2369mq2 = (C2369mq) obj;
                    try {
                        c2369mq2.a.x0(new com.google.android.gms.dynamic.b(context2), zzrVar2, c2023eq2.d, jSONObject.toString(), com.google.android.gms.internal.mlkit_vision_common.V2.j(yp), (InterfaceC1671Ca) iInterface);
                        return;
                    } finally {
                    }
                }
                C2369mq c2369mq3 = (C2369mq) obj;
                try {
                    c2369mq3.a.Z0(new com.google.android.gms.dynamic.b(context2), zzrVar2, c2023eq2.d, jSONObject.toString(), com.google.android.gms.internal.mlkit_vision_common.V2.j(yp), (InterfaceC1671Ca) iInterface);
                    return;
                } finally {
                }
            default:
                C2369mq c2369mq4 = (C2369mq) c2880ym.b;
                C2023eq c2023eq3 = (C2023eq) c1849aq.a.b;
                String string2 = vp.v.toString();
                String strJ = com.google.android.gms.internal.mlkit_vision_common.V2.j(vp.s);
                Context context3 = this.b;
                InterfaceC1671Ca interfaceC1671Ca2 = (InterfaceC1671Ca) c2880ym.c;
                zzbfv zzbfvVar = c2023eq3.i;
                ArrayList arrayList = c2023eq3.g;
                try {
                    c2369mq4.a.W3(new com.google.android.gms.dynamic.b(context3), c2023eq3.d, string2, strJ, interfaceC1671Ca2, zzbfvVar, arrayList);
                    return;
                } finally {
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final Object b(C1849aq c1849aq, Vp vp, C2880ym c2880ym) throws zzfcw {
        zzfcw zzfcwVar;
        View view;
        Executor executor = this.d;
        Object obj = this.c;
        switch (this.a) {
            case 0:
                C2326lq c2326lq = new C2326lq(c1849aq, vp, c2880ym.a);
                Fi fi = new Fi(15, new Fm(c2880ym, vp, 0), null);
                com.airbnb.lottie.parser.l lVar = new com.airbnb.lottie.parser.l(vp.a0, 3);
                C1777Te c1777Te = (C1777Te) obj;
                C1765Re c1765Re = c1777Te.c;
                C1777Te c1777Te2 = c1777Te.d;
                C1771Se c1771Se = new C1771Se(c1765Re, c1777Te2, c2326lq, fi, lVar);
                ((C2403nh) c1771Se.F.zzb()).i1(new C2744vf((C2369mq) c2880ym.b, 0), (Xv) executor);
                ((Rm) c2880ym.c).f4(new BinderC2795wn((Vg) c1771Se.M.zzb(), (C2404ni) c1771Se.O.zzb(), (C2146hh) c1771Se.I.zzb(), (C2489ph) c1771Se.L.zzb(), (C2574rh) c1771Se.P.zzb(), (Qh) c1777Te2.G0.zzb(), (C2875yh) c1771Se.Q.zzb(), (C2704ui) c1771Se.R.zzb(), (Oh) c1771Se.S.zzb(), (C2058fh) c1771Se.U.zzb()));
                return c1771Se.O();
            case 1:
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S7)).booleanValue();
                Object obj2 = c2880ym.b;
                if (zBooleanValue && vp.g0) {
                    try {
                        C1677Da c1677DaI = ((C2369mq) obj2).a.i();
                        if (c1677DaI == null) {
                            com.google.android.gms.ads.internal.util.client.i.e("getInterscrollerAd should not be null after loadInterscrollerAd loaded ad.");
                            throw new zzfcw(new Exception("getInterscrollerAd should not be null after loadInterscrollerAd loaded ad."));
                        }
                        try {
                            view = (View) com.google.android.gms.dynamic.b.I3(c1677DaI.h4());
                            Parcel parcelY3 = c1677DaI.Y3(2, c1677DaI.f3());
                            ClassLoader classLoader = AbstractC2857y5.a;
                            boolean z = parcelY3.readInt() != 0;
                            parcelY3.recycle();
                            if (view == null) {
                                throw new zzfcw(new Exception("BannerAdapterWrapper interscrollerView should not be null"));
                            }
                            if (z) {
                                try {
                                    view = (View) AbstractC2025es.N(Tv.b, new C2616sg(this, view, vp, 5), AbstractC2270kd.f).get();
                                } catch (InterruptedException | ExecutionException e) {
                                    throw new zzfcw(e);
                                }
                            }
                        } catch (RemoteException e2) {
                            throw new zzfcw(e2);
                        }
                    } finally {
                    }
                } else {
                    try {
                        view = (View) com.google.android.gms.dynamic.b.I3(((C2369mq) obj2).a.m());
                    } finally {
                    }
                }
                C2326lq c2326lq2 = new C2326lq(c1849aq, vp, c2880ym.a);
                C2369mq c2369mq = (C2369mq) obj2;
                com.google.firebase.messaging.u uVar = new com.google.firebase.messaging.u(view, (InterfaceC2529qe) null, new C2881yn(c2369mq, 22), (Wp) vp.u.get(0));
                C1789Ve c1789Ve = (C1789Ve) obj;
                C1765Re c1765Re2 = c1789Ve.d;
                C1789Ve c1789Ve2 = c1789Ve.e;
                C1783Ue c1783Ue = new C1783Ue(c1765Re2, c1789Ve2, c2326lq2, uVar);
                ((C2361mi) c1783Ue.X.zzb()).k1(view);
                ((C2403nh) c1783Ue.F.zzb()).i1(new C2744vf(c2369mq, 0), executor);
                ((Rm) c2880ym.c).f4(new BinderC2795wn((Vg) c1783Ue.J.zzb(), (C2404ni) c1783Ue.P.zzb(), (C2146hh) c1783Ue.M.zzb(), (C2489ph) c1783Ue.I.zzb(), c1783Ue.P(), (Qh) c1789Ve2.U0.zzb(), (C2875yh) c1783Ue.S.zzb(), (C2704ui) c1783Ue.T.zzb(), (Oh) c1783Ue.U.zzb(), (C2058fh) c1783Ue.V.zzb()));
                return c1783Ue.O();
            default:
                return c(c1849aq, vp, c2880ym);
        }
    }
}
