package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Om implements Am {
    public final /* synthetic */ int a = 1;
    public final Context b;
    public final Object c;
    public Object d;
    public Object e;

    public Om(Context context, VersionInfoParcel versionInfoParcel, C1813Ze c1813Ze, Xv xv) {
        this.b = context;
        this.d = versionInfoParcel;
        this.c = c1813Ze;
        this.e = xv;
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final void a(C1849aq c1849aq, Vp vp, C2880ym c2880ym) throws JSONException, zzfcw, IOException {
        switch (this.a) {
            case 0:
                try {
                    InterfaceC1965db interfaceC1965db = (InterfaceC1965db) c2880ym.b;
                    interfaceC1965db.D3(vp.Z);
                    boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S7)).booleanValue();
                    IInterface iInterface = c2880ym.c;
                    Context context = this.b;
                    JSONObject jSONObject = vp.v;
                    if (zBooleanValue && vp.g0) {
                        String str = vp.U;
                        String string = jSONObject.toString();
                        C2023eq c2023eq = (C2023eq) c1849aq.a.b;
                        interfaceC1965db.K3(str, string, c2023eq.d, new com.google.android.gms.dynamic.b(context), new Nm(this, c2880ym), (InterfaceC1671Ca) iInterface, c2023eq.e);
                        return;
                    }
                    String str2 = vp.U;
                    String string2 = jSONObject.toString();
                    C2023eq c2023eq2 = (C2023eq) c1849aq.a.b;
                    interfaceC1965db.l2(str2, string2, c2023eq2.d, new com.google.android.gms.dynamic.b(context), new Nm(this, c2880ym), (InterfaceC1671Ca) iInterface, c2023eq2.e);
                    return;
                } catch (RemoteException th) {
                    throw new zzfcw(th);
                }
            case 1:
                C2369mq c2369mq = (C2369mq) c2880ym.b;
                C2023eq c2023eq3 = (C2023eq) c1849aq.a.b;
                String string3 = vp.v.toString();
                String strJ = com.google.android.gms.internal.mlkit_vision_common.V2.j(vp.s);
                Context context2 = this.b;
                InterfaceC1671Ca interfaceC1671Ca = (InterfaceC1671Ca) c2880ym.c;
                try {
                    c2369mq.a.c4(new com.google.android.gms.dynamic.b(context2), c2023eq3.d, string3, strJ, interfaceC1671Ca);
                    return;
                } finally {
                    zzfcw zzfcwVar = new zzfcw(th);
                }
            default:
                try {
                    InterfaceC1965db interfaceC1965db2 = (InterfaceC1965db) c2880ym.b;
                    interfaceC1965db2.D3(vp.Z);
                    int i = ((VersionInfoParcel) this.e).c;
                    int iIntValue = ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K1)).intValue();
                    IInterface iInterface2 = c2880ym.c;
                    Context context3 = this.b;
                    JSONObject jSONObject2 = vp.v;
                    if (i < iIntValue) {
                        interfaceC1965db2.O0(vp.U, jSONObject2.toString(), ((C2023eq) c1849aq.a.b).d, new com.google.android.gms.dynamic.b(context3), new BinderC1846an(this, c2880ym), (InterfaceC1671Ca) iInterface2);
                        return;
                    }
                    String str3 = vp.U;
                    String string4 = jSONObject2.toString();
                    C2023eq c2023eq4 = (C2023eq) c1849aq.a.b;
                    interfaceC1965db2.u1(str3, string4, c2023eq4.d, new com.google.android.gms.dynamic.b(context3), new BinderC1846an(this, c2880ym), (InterfaceC1671Ca) iInterface2, c2023eq4.i);
                    return;
                } catch (RemoteException th2) {
                    throw new zzfcw(th2);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final Object b(C1849aq c1849aq, Vp vp, C2880ym c2880ym) throws zzfcw, zzegy {
        View view;
        int i = 9;
        Object obj = this.c;
        Object obj2 = null;
        int i2 = 17;
        int i3 = 3;
        int i4 = 0;
        switch (this.a) {
            case 0:
                boolean z = true;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S7)).booleanValue() && vp.g0) {
                    try {
                        view = (View) com.google.android.gms.dynamic.b.I3(((C1677Da) this.e).h4());
                        C1677Da c1677Da = (C1677Da) this.e;
                        Parcel parcelY3 = c1677Da.Y3(2, c1677Da.f3());
                        ClassLoader classLoader = AbstractC2857y5.a;
                        if (parcelY3.readInt() == 0) {
                            z = false;
                        }
                        parcelY3.recycle();
                        if (view == null) {
                            throw new zzfcw(new Exception("BannerRtbAdapterWrapper interscrollerView should not be null"));
                        }
                        if (z) {
                            try {
                                view = (View) AbstractC2025es.N(Tv.b, new C2616sg(this, view, vp, 6), AbstractC2270kd.f).get();
                            } catch (InterruptedException | ExecutionException e) {
                                throw new zzfcw(e);
                            }
                        }
                    } catch (RemoteException e2) {
                        throw new zzfcw(e2);
                    }
                } else {
                    view = (View) this.d;
                }
                C2326lq c2326lq = new C2326lq(c1849aq, vp, c2880ym.a);
                com.google.firebase.messaging.u uVar = new com.google.firebase.messaging.u(view, (InterfaceC2529qe) null, new Os(c2880ym, 24), (Wp) vp.u.get(0));
                C1789Ve c1789Ve = (C1789Ve) obj;
                C1765Re c1765Re = c1789Ve.d;
                C1789Ve c1789Ve2 = c1789Ve.e;
                C1783Ue c1783Ue = new C1783Ue(c1765Re, c1789Ve2, c2326lq, uVar);
                ((C2361mi) c1783Ue.X.zzb()).k1(view);
                ((Rm) c2880ym.c).f4(new BinderC2709un((Vg) c1783Ue.J.zzb(), (C2404ni) c1783Ue.P.zzb(), (C2146hh) c1783Ue.M.zzb(), (C2489ph) c1783Ue.I.zzb(), c1783Ue.P(), (Qh) c1789Ve2.U0.zzb(), (C2875yh) c1783Ue.S.zzb(), (C2704ui) c1783Ue.T.zzb(), (Oh) c1783Ue.U.zzb(), (C2058fh) c1783Ue.V.zzb()));
                return c1783Ue.O();
            case 1:
                C2326lq c2326lq2 = new C2326lq(c1849aq, vp, c2880ym.a);
                Fi fi = new Fi(15, new C2326lq(this, c2880ym, vp, 20), obj2);
                C1813Ze c1813Ze = (C1813Ze) obj;
                C1765Re c1765Re2 = c1813Ze.b;
                C1813Ze c1813Ze2 = c1813Ze.c;
                C1807Ye c1807Ye = new C1807Ye(c1765Re2, c1813Ze2, c2326lq2, fi);
                ((C2403nh) c1807Ye.E.zzb()).i1(new C2744vf((C2369mq) c2880ym.b, 0), (Xv) this.e);
                ((Rm) c2880ym.c).f4(new BinderC2795wn((Vg) c1807Ye.L.zzb(), (C2404ni) c1807Ye.O.zzb(), (C2146hh) c1807Ye.H.zzb(), (C2489ph) c1807Ye.K.zzb(), (C2574rh) c1807Ye.P.zzb(), (Qh) c1813Ze2.N0.zzb(), (C2875yh) c1807Ye.R.zzb(), (C2704ui) c1807Ye.S.zzb(), (Oh) c1807Ye.T.zzb(), (C2058fh) c1807Ye.V.zzb()));
                return c1807Ye.O();
            default:
                ArrayList arrayList = ((C2023eq) c1849aq.a.b).g;
                if (!arrayList.contains(Integer.toString(6))) {
                    throw new zzegy(2, "Unified must be used for RTB.");
                }
                Yi yiN = Yi.n((InterfaceC1707Ia) this.d);
                if (!arrayList.contains(Integer.toString(yiN.g()))) {
                    throw new zzegy(1, "No corresponding native ad listener");
                }
                C2326lq c2326lq3 = new C2326lq(c1849aq, vp, c2880ym.a);
                S4 s4 = new S4(yiN, i2);
                C2326lq c2326lq4 = new C2326lq((C1689Fa) null, (C1683Ea) null, (InterfaceC1707Ia) this.d);
                C1759Qe c1759Qe = (C1759Qe) obj;
                C1765Re c1765Re3 = c1759Qe.b;
                C2702ug c2702ug = new C2702ug(c2326lq3, 0);
                C1759Qe c1759Qe2 = c1759Qe.c;
                BC bc = c1759Qe2.F;
                H5 h5 = c1765Re3.B0;
                BC bcB = BC.b(new Mg(bc, c2702ug, i4));
                BC bcB2 = BC.b(new C2874yg(bcB, 16));
                int i5 = IC.c;
                ArrayList arrayList2 = new ArrayList(1);
                ArrayList arrayList3 = new ArrayList(2);
                arrayList3.add(c1759Qe2.u0);
                arrayList3.add(c1759Qe2.v0);
                arrayList2.add(bcB2);
                BC bcB3 = BC.b(new Wg(new IC(arrayList2, arrayList3), i3));
                BC bcB4 = BC.b(AbstractC2096gb.m);
                BC bc2 = c1765Re3.c;
                BC bcB5 = BC.b(new C1730Lf(bcB4, bc2, i));
                C2702ug c2702ug2 = new C2702ug(c2326lq3, 3);
                C2702ug c2702ug3 = new C2702ug(c2326lq3, 2);
                C1741Ne c1741Ne = c1765Re3.g;
                BC bcB6 = BC.b(new C2873yf(c1765Re3.G, c1765Re3.F, c2702ug, c2702ug3, BC.b(new C2873yf(c1741Ne, c1765Re3.R, BC.b(new C1735Me(c1741Ne, 14)), BC.b(AbstractC1795We.p), c1765Re3.w0, c1765Re3.d)), c1759Qe2.e));
                C2016ej c2016ej = new C2016ej(2);
                C2016ej c2016ej2 = new C2016ej(0);
                BC bcB7 = BC.b(new C1730Lf(bcB4, bc2, 14));
                BC bcB8 = BC.b(LA.o);
                C2833xi c2833xi = new C2833xi(bcB8, 10);
                ArrayList arrayList4 = new ArrayList(2);
                ArrayList arrayList5 = new ArrayList(1);
                arrayList5.add(c1759Qe2.A0);
                arrayList4.add(bcB7);
                arrayList4.add(c2833xi);
                BC bcB9 = BC.b(new C1703Hc(new IC(arrayList4, arrayList5), c2702ug, c2702ug2, 7));
                BC bcB10 = BC.b(new Cif(c1765Re3.g, c1765Re3.c, c1765Re3.d, c2702ug2, c2702ug, c1759Qe2.q0, bcB6, c2016ej, c2016ej2, c1765Re3.C, c1759Qe2.r0, c1759Qe2.e, c1759Qe2.z0, bcB9));
                int i6 = 3;
                C2874yg c2874yg = new C2874yg(bcB10, i6);
                C2874yg c2874yg2 = new C2874yg(BC.b(new C1691Fc(c2702ug, c1765Re3.P, i6)), 22);
                ArrayList arrayList6 = new ArrayList(4);
                ArrayList arrayList7 = new ArrayList(2);
                arrayList6.add(c1759Qe2.w0);
                arrayList7.add(c1759Qe2.x0);
                arrayList7.add(c1759Qe2.y0);
                arrayList6.add(bcB5);
                arrayList6.add(c2874yg);
                arrayList6.add(c2874yg2);
                BC bcB11 = BC.b(new Wg(new IC(arrayList6, arrayList7), 4));
                BC bcB12 = BC.b(new Ig(c1765Re3.g, c1765Re3.v0, c1765Re3.x, c2702ug2, c2702ug, c1765Re3.E, AbstractC1972di.C));
                BC bcB13 = BC.b(new C2874yg(bcB12, 14));
                BC bcB14 = BC.b(new C1730Lf(bcB4, bc2, 8));
                BC bcB15 = BC.b(new C2874yg(BC.b(new Bg(c1765Re3.r0, c1759Qe2.d, 0)), 12));
                C2874yg c2874yg3 = new C2874yg(bcB10, 2);
                ArrayList arrayList8 = new ArrayList(5);
                ArrayList arrayList9 = new ArrayList(3);
                arrayList8.add(c1759Qe2.B0);
                arrayList8.add(c1759Qe2.C0);
                arrayList9.add(c1759Qe2.D0);
                arrayList9.add(c1759Qe2.E0);
                arrayList8.add(bcB13);
                arrayList8.add(bcB14);
                arrayList9.add(bcB15);
                arrayList8.add(c2874yg3);
                BC bcB16 = BC.b(new Wg(new IC(arrayList8, arrayList9), 0));
                BC bcB17 = BC.b(new C2874yg(bcB12, 15));
                BC bcB18 = BC.b(new C1730Lf(bcB4, bc2, 11));
                C1729Le c1729Le = new C1729Le(bcB9, 21);
                C2874yg c2874yg4 = new C2874yg(bcB10, 5);
                ArrayList arrayList10 = new ArrayList(6);
                ArrayList arrayList11 = new ArrayList(2);
                arrayList10.add(c1759Qe2.F0);
                arrayList10.add(c1759Qe2.G0);
                arrayList11.add(c1759Qe2.H0);
                arrayList11.add(c1759Qe2.I0);
                arrayList10.add(bcB17);
                arrayList10.add(bcB18);
                arrayList10.add(c1729Le);
                arrayList10.add(c2874yg4);
                BC bcB19 = BC.b(new Wg(new IC(arrayList10, arrayList11), 2));
                C2874yg c2874yg5 = new C2874yg(bcB10, 8);
                ArrayList arrayList12 = new ArrayList(1);
                ArrayList arrayList13 = new ArrayList(1);
                arrayList13.add(c1759Qe2.J0);
                arrayList12.add(c2874yg5);
                BC bcB20 = BC.b(new Wg(new IC(arrayList12, arrayList13), 19));
                C2874yg c2874yg6 = new C2874yg(BC.b(new Mg(c2702ug, c1765Re3.G)), 1);
                ArrayList arrayList14 = new ArrayList(1);
                new ArrayList(1).add(c1759Qe2.K0);
                arrayList14.add(c2874yg6);
                BC bcB21 = BC.b(new C1730Lf(bcB4, bc2, 15));
                ArrayList arrayList15 = new ArrayList(1);
                ArrayList arrayList16 = new ArrayList(1);
                arrayList16.add(c1759Qe2.L0);
                arrayList15.add(bcB21);
                BC bcB22 = BC.b(new Wg(new IC(arrayList15, arrayList16), 20));
                BC bcB23 = BC.b(new C2874yg(bcB, 17));
                C2874yg c2874yg7 = new C2874yg(bcB10, 6);
                ArrayList arrayList17 = new ArrayList(7);
                ArrayList arrayList18 = new ArrayList(4);
                arrayList17.add(c1759Qe2.M0);
                arrayList18.add(c1759Qe2.N0);
                arrayList17.add(c1759Qe2.O0);
                arrayList17.add(c1759Qe2.P0);
                arrayList18.add(c1759Qe2.Q0);
                arrayList18.add(c1759Qe2.R0);
                arrayList18.add(c1759Qe2.S0);
                arrayList17.add(c1759Qe2.T0);
                arrayList17.add(c1759Qe2.U0);
                arrayList17.add(bcB23);
                arrayList17.add(c2874yg7);
                BC bcB24 = BC.b(new Wg(new IC(arrayList17, arrayList18), 5));
                C2874yg c2874yg8 = new C2874yg(BC.b(new C1729Le(bcB11, 20)), 10);
                BC bcB25 = BC.b(new C1730Lf(bcB4, bc2, 13));
                ArrayList arrayList19 = new ArrayList(2);
                ArrayList arrayList20 = new ArrayList(1);
                arrayList20.add(c1759Qe2.W0);
                arrayList19.add(c2874yg8);
                arrayList19.add(bcB25);
                BC bcB26 = BC.b(new Wg(new IC(arrayList19, arrayList20), 9));
                C1969df c1969df = new C1969df(s4, 15);
                C1691Fc c1691Fc = new C1691Fc(new Pi(c1969df, 1), bc2, 14);
                ArrayList arrayList21 = new ArrayList(1);
                ArrayList arrayList22 = new ArrayList(1);
                arrayList22.add(c1759Qe2.X0);
                arrayList21.add(c1691Fc);
                BC bcB27 = BC.b(new Wg(new IC(arrayList21, arrayList22), 24));
                BC bcB28 = BC.b(new C2874yg(bcB12, 13));
                ArrayList arrayList23 = new ArrayList(1);
                List list = Collections.EMPTY_LIST;
                arrayList23.add(bcB28);
                BC bcB29 = BC.b(new Wg(new IC(arrayList23, list), 13));
                BC bcB30 = BC.b(new C1730Lf(bcB4, bc2, 10));
                C2874yg c2874yg9 = new C2874yg(bcB10, 4);
                ArrayList arrayList24 = new ArrayList(2);
                ArrayList arrayList25 = new ArrayList(1);
                arrayList25.add(c1759Qe2.Y0);
                arrayList24.add(bcB30);
                arrayList24.add(c2874yg9);
                Wg wg = new Wg(new IC(arrayList24, arrayList25), 1);
                BC bcB31 = BC.b(new C2874yg(bcB12, 9));
                ArrayList arrayList26 = new ArrayList(1);
                List list2 = Collections.EMPTY_LIST;
                arrayList26.add(bcB31);
                BC bcB32 = BC.b(new C1703Hc(wg, new IC(arrayList26, list2), c1765Re3.d, 6));
                C2702ug c2702ug4 = new C2702ug(c2326lq3, 1);
                com.google.android.gms.ads.nonagon.signalgeneration.t tVar = new com.google.android.gms.ads.nonagon.signalgeneration.t(c2702ug, c2702ug4, c1759Qe2.I, c2702ug3, c1759Qe2.f);
                ArrayList arrayList27 = new ArrayList(1);
                ArrayList arrayList28 = new ArrayList(1);
                arrayList28.add(c1759Qe2.a1);
                arrayList27.add(c1759Qe2.b1);
                com.google.android.gms.ads.nonagon.signalgeneration.n nVar = new com.google.android.gms.ads.nonagon.signalgeneration.n(c2702ug2, c2702ug, bcB3, bcB24, c1759Qe2.Z0, tVar, bcB4, new Wg(new IC(arrayList27, arrayList28), 6), bcB20);
                C2834xj c2834xj = new C2834xj(c2326lq4, 0);
                C2834xj c2834xj2 = new C2834xj(c2326lq4, 1);
                C2834xj c2834xj3 = new C2834xj(c2326lq4, 2);
                Tg tg = c1759Qe2.d;
                BC bc3 = c1759Qe2.F;
                C1741Ne c1741Ne2 = c1765Re3.j;
                C2833xi c2833xi2 = new C2833xi(BC.b(new C1784Uf(c2834xj, c2834xj2, c2834xj3, bcB19, bcB16, bcB22, bc3, c2702ug, c1741Ne2, tg)), 12);
                BC bcB33 = BC.b(new C1742Nf(c2702ug, 1));
                C2016ej c2016ej3 = new C2016ej(3);
                C2016ej c2016ej4 = new C2016ej(4);
                BC bcB34 = BC.b(new C1969df(new Pi(c1969df, 0), 14));
                C1729Le c1729Le2 = c1765Re3.R;
                BC bc4 = c1765Re3.c;
                C2233jj c2233jj = new C2233jj(c1729Le2, tg, bcB33, c1969df, c2016ej3, c2016ej4, bc4, bcB34);
                C2153ho c2153ho = new C2153ho();
                BC bcB35 = BC.b(new Sj(c2702ug4, c2153ho, c1969df, 1));
                BC bcB36 = BC.b(new Sj(c2702ug4, c2153ho, c1969df, 0));
                BC bcB37 = BC.b(new C1760Qf(c2702ug4, c2153ho, c1969df, c1765Re3.x));
                BC bcB38 = BC.b(new C1691Fc(c2153ho, c1969df, 17));
                C1741Ne c1741Ne3 = c1765Re3.g;
                C2153ho.a(c2153ho, BC.b(new Vi(nVar, bc4, c1969df, c2833xi2, c2233jj, bcB33, c1759Qe2.l0, bcB35, bcB36, bcB37, bcB38, BC.b(new C1760Qf(c1741Ne3, c1969df, c2233jj, c2153ho, 6)), new C1839ag(c1741Ne3, tg, 2), c1765Re3.C, c1741Ne2, c1741Ne3, bcB34, bcB8, c1765Re3.I0)));
                ((Rm) c2880ym.c).f4(new BinderC2709un((Vg) bcB16.zzb(), (C2404ni) bcB22.zzb(), (C2146hh) bcB19.zzb(), (C2489ph) bcB11.zzb(), (C2574rh) bcB24.zzb(), (Qh) c1759Qe2.V0.zzb(), (C2875yh) bcB26.zzb(), (C2704ui) bcB27.zzb(), (Oh) bcB29.zzb(), (C2058fh) bcB32.zzb()));
                return (Ui) c2153ho.zzb();
        }
    }

    public Om(Context context, C1759Qe c1759Qe, VersionInfoParcel versionInfoParcel) {
        this.b = context;
        this.c = c1759Qe;
        this.e = versionInfoParcel;
    }

    public Om(Context context, C1789Ve c1789Ve) {
        this.b = context;
        this.c = c1789Ve;
    }
}
