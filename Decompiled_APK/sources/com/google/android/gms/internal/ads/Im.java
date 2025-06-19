package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IInterface;
import android.os.RemoteException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Im implements Am {
    public final /* synthetic */ int a;
    public final Context b;
    public final Object c;

    public /* synthetic */ Im(int i, Context context, Object obj) {
        this.a = i;
        this.b = context;
        this.c = obj;
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final void a(C1849aq c1849aq, Vp vp, C2880ym c2880ym) throws zzfcw {
        switch (this.a) {
            case 0:
                try {
                    InterfaceC1965db interfaceC1965db = (InterfaceC1965db) c2880ym.b;
                    interfaceC1965db.D3(vp.Z);
                    interfaceC1965db.L3(vp.U, vp.v.toString(), ((C2023eq) c1849aq.a.b).d, new com.google.android.gms.dynamic.b(this.b), new Hm(c2880ym), (InterfaceC1671Ca) c2880ym.c);
                    return;
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.A.m();
                    throw new zzfcw(e);
                }
            case 1:
                try {
                    InterfaceC1965db interfaceC1965db2 = (InterfaceC1965db) c2880ym.b;
                    interfaceC1965db2.D3(vp.Z);
                    interfaceC1965db2.o1(vp.U, vp.v.toString(), ((C2023eq) c1849aq.a.b).d, new com.google.android.gms.dynamic.b(this.b), new Wm(c2880ym), (InterfaceC1671Ca) c2880ym.c);
                    return;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.A.m();
                    throw new zzfcw(e2);
                }
            default:
                try {
                    InterfaceC1965db interfaceC1965db3 = (InterfaceC1965db) c2880ym.b;
                    interfaceC1965db3.D3(vp.Z);
                    C2023eq c2023eq = (C2023eq) c1849aq.a.b;
                    int i = c2023eq.o.b;
                    IInterface iInterface = c2880ym.c;
                    Context context = this.b;
                    JSONObject jSONObject = vp.v;
                    if (i == 3) {
                        interfaceC1965db3.L1(vp.U, jSONObject.toString(), c2023eq.d, new com.google.android.gms.dynamic.b(context), new BinderC2366mn(c2880ym), (InterfaceC1671Ca) iInterface);
                    } else {
                        interfaceC1965db3.Z1(vp.U, jSONObject.toString(), c2023eq.d, new com.google.android.gms.dynamic.b(context), new BinderC2366mn(c2880ym), (InterfaceC1671Ca) iInterface);
                    }
                    return;
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                    return;
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final Object b(C1849aq c1849aq, Vp vp, C2880ym c2880ym) {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(vp, (InterfaceC1965db) c2880ym.b, com.google.android.gms.ads.c.APP_OPEN_AD);
                C2326lq c2326lq = new C2326lq(c1849aq, vp, c2880ym.a);
                Fi fi = new Fi(15, jVar, null);
                com.airbnb.lottie.parser.l lVar = new com.airbnb.lottie.parser.l(vp.a0, 3);
                C1777Te c1777Te = (C1777Te) this.c;
                C1765Re c1765Re = c1777Te.c;
                C1777Te c1777Te2 = c1777Te.d;
                C1771Se c1771Se = new C1771Se(c1765Re, c1777Te2, c2326lq, fi, lVar);
                BC bc = c1771Se.I;
                jVar.d = (C2146hh) bc.zzb();
                ((Rm) c2880ym.c).f4(new BinderC2709un((Vg) c1771Se.M.zzb(), (C2404ni) c1771Se.O.zzb(), (C2146hh) bc.zzb(), (C2489ph) c1771Se.L.zzb(), (C2574rh) c1771Se.P.zzb(), (Qh) c1777Te2.G0.zzb(), (C2875yh) c1771Se.Q.zzb(), (C2704ui) c1771Se.R.zzb(), (Oh) c1771Se.S.zzb(), (C2058fh) c1771Se.U.zzb()));
                return c1771Se.O();
            case 1:
                com.quizlet.data.repository.metering.j jVar2 = new com.quizlet.data.repository.metering.j(vp, (InterfaceC1965db) c2880ym.b, com.google.android.gms.ads.c.INTERSTITIAL);
                C2326lq c2326lq2 = new C2326lq(c1849aq, vp, c2880ym.a);
                Fi fi2 = new Fi(15, jVar2, null);
                C1813Ze c1813Ze = (C1813Ze) this.c;
                C1765Re c1765Re2 = c1813Ze.b;
                C1813Ze c1813Ze2 = c1813Ze.c;
                C1807Ye c1807Ye = new C1807Ye(c1765Re2, c1813Ze2, c2326lq2, fi2);
                BC bc2 = c1807Ye.H;
                jVar2.d = (C2146hh) bc2.zzb();
                ((Rm) c2880ym.c).f4(new BinderC2709un((Vg) c1807Ye.L.zzb(), (C2404ni) c1807Ye.O.zzb(), (C2146hh) bc2.zzb(), (C2489ph) c1807Ye.K.zzb(), (C2574rh) c1807Ye.P.zzb(), (Qh) c1813Ze2.N0.zzb(), (C2875yh) c1807Ye.R.zzb(), (C2704ui) c1807Ye.S.zzb(), (Oh) c1807Ye.T.zzb(), (C2058fh) c1807Ye.V.zzb()));
                return c1807Ye.O();
            default:
                com.quizlet.data.repository.metering.j jVar3 = new com.quizlet.data.repository.metering.j(vp, (InterfaceC1965db) c2880ym.b, com.google.android.gms.ads.c.REWARDED);
                C2326lq c2326lq3 = new C2326lq(c1849aq, vp, c2880ym.a);
                C2149hk c2149hk = new C2149hk(jVar3, null, 0);
                C1882bf c1882bf = (C1882bf) this.c;
                C1765Re c1765Re3 = c1882bf.c;
                C1882bf c1882bf2 = c1882bf.d;
                C1838af c1838af = new C1838af(c1765Re3, c1882bf2, c2326lq3, c2149hk);
                BC bc3 = c1838af.H;
                jVar3.d = (C2146hh) bc3.zzb();
                ((Rm) c2880ym.c).f4(new BinderC2666tn((Vg) c1838af.L.zzb(), (C2404ni) c1838af.N.zzb(), (C2146hh) bc3.zzb(), (C2489ph) c1838af.K.zzb(), (C2574rh) c1838af.O.zzb(), (C2058fh) c1838af.U.zzb(), (Qh) c1882bf2.K0.zzb(), (C2704ui) c1838af.R.zzb(), (C2875yh) c1838af.Q.zzb(), (C2575ri) c1838af.W.zzb(), (Oh) c1838af.S.zzb()));
                return c1838af.O();
        }
    }
}
