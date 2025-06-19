package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import com.google.android.gms.ads.internal.util.C1633i;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.sg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2616sg implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ C2616sg(InterfaceC2751vm interfaceC2751vm, Vp vp, C1849aq c1849aq, C2147hi c2147hi, int i) {
        this.a = i;
        this.b = interfaceC2751vm;
        this.c = vp;
        this.d = c1849aq;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) throws JSONException {
        switch (this.a) {
            case 0:
                AbstractC2359mg abstractC2359mg = (AbstractC2359mg) obj;
                if (abstractC2359mg != null) {
                    ((com.quizlet.remote.model.notes.e) this.c).mo15c(abstractC2359mg);
                }
                return AbstractC2025es.O((com.google.common.util.concurrent.e) this.d, ((Long) AbstractC2174i8.a.o()).longValue(), TimeUnit.MILLISECONDS, ((C2659tg) this.b).b);
            case 1:
                Oj oj = (Oj) this.b;
                InterfaceC2529qe interfaceC2529qeA = oj.c.a(com.google.android.gms.ads.internal.client.zzr.b(), null, null);
                C2257k6 c2257k6 = new C2257k6(interfaceC2529qeA);
                oj.a(interfaceC2529qeA, (com.google.android.gms.ads.internal.a) this.c, (C1673Cc) this.d);
                interfaceC2529qeA.L().h = new Ej(c2257k6);
                interfaceC2529qeA.loadUrl((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S3));
                return c2257k6;
            case 2:
                String str = (String) this.c;
                JSONObject jSONObject = (JSONObject) this.d;
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                C2217j9 c2217j9 = ((C1843ak) this.b).h;
                c2217j9.getClass();
                C2313ld c2313ld = new C2313ld();
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                String string = UUID.randomUUID().toString();
                c2217j9.a(string, new C2732v9(c2313ld, 0));
                try {
                    JSONObject jSONObject2 = new JSONObject();
                    jSONObject2.put("id", string);
                    jSONObject2.put("args", jSONObject);
                    interfaceC2529qe.d(str, jSONObject2);
                } catch (Exception e) {
                    c2313ld.d(e);
                }
                return c2313ld;
            case 3:
                C2601s7 c2601s7 = AbstractC2773w7.k2;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
                Cm cm = (Cm) this.b;
                if (zBooleanValue) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, cm.i.d, "rendering-webview-creation-start");
                }
                C2406nk c2406nk = cm.b;
                C1849aq c1849aq = (C1849aq) this.d;
                androidx.work.impl.model.n nVar = c1849aq.b;
                C2023eq c2023eq = cm.c;
                Vp vp = (Vp) this.c;
                final InterfaceC2529qe interfaceC2529qeA2 = c2406nk.a(c2023eq.e, vp, (Xp) nVar.b);
                interfaceC2529qeA2.D(vp.W);
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                boolean zBooleanValue2 = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue();
                Ek ek = cm.i;
                if (zBooleanValue2) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek.d, "rendering-webview-creation-end");
                }
                C2313ld c2313ld2 = new C2313ld();
                C2326lq c2326lq = new C2326lq(c1849aq, vp, (String) null);
                VersionInfoParcel versionInfoParcel = cm.e;
                C2475p9 c2475p9 = cm.f;
                boolean z = cm.g;
                C2475p9 c2475p92 = c2475p9;
                Fi fi = new Fi(15, new Em(versionInfoParcel, c2313ld2, vp, interfaceC2529qeA2, c2023eq, z, c2475p9, cm.h, cm.j), interfaceC2529qeA2);
                com.airbnb.lottie.parser.l lVar = new com.airbnb.lottie.parser.l(vp.a0, 3);
                C1777Te c1777Te = cm.a;
                C1771Se c1771Se = new C1771Se(c1777Te.c, c1777Te.d, c2326lq, fi, lVar);
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek.d, "rendering-ad-component-creation-end");
                }
                BC bc = c1771Se.V;
                C2363mk c2363mk = (C2363mk) bc.zzb();
                if (true != z) {
                    c2475p92 = null;
                }
                c2363mk.a(interfaceC2529qeA2, false, c2475p92, ek.d);
                c2313ld2.c(c1771Se);
                final int i = 0;
                ((C2146hh) c1771Se.I.zzb()).i1(new InterfaceC2189ih() { // from class: com.google.android.gms.internal.ads.Bm
                    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
                    public final void K() {
                        switch (i) {
                            case 0:
                                InterfaceC2529qe interfaceC2529qe2 = interfaceC2529qeA2;
                                if (interfaceC2529qe2.L() != null) {
                                    interfaceC2529qe2.L().m0();
                                    break;
                                }
                                break;
                            case 1:
                                InterfaceC2529qe interfaceC2529qe3 = interfaceC2529qeA2;
                                if (interfaceC2529qe3.L() != null) {
                                    interfaceC2529qe3.L().m0();
                                    break;
                                }
                                break;
                            case 2:
                                InterfaceC2529qe interfaceC2529qe4 = interfaceC2529qeA2;
                                if (interfaceC2529qe4.L() != null) {
                                    interfaceC2529qe4.L().m0();
                                    break;
                                }
                                break;
                            default:
                                InterfaceC2529qe interfaceC2529qe5 = interfaceC2529qeA2;
                                if (interfaceC2529qe5.L() != null) {
                                    interfaceC2529qe5.L().m0();
                                    break;
                                }
                                break;
                        }
                    }
                }, AbstractC2270kd.g);
                Yp yp = vp.s;
                String strB = yp.a;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.n5)).booleanValue() && ((C2622sm) c1771Se.H.zzb()).c()) {
                    strB = AbstractC1675Ce.b(strB, AbstractC1675Ce.a(vp));
                }
                return AbstractC2025es.L(C2363mk.b(interfaceC2529qeA2, yp.b, strB, ek.d), new Jg(interfaceC2529qeA2, vp, c1771Se, 1), cm.d);
            case 4:
                C2601s7 c2601s72 = AbstractC2773w7.k2;
                com.google.android.gms.ads.internal.client.r rVar2 = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue3 = ((Boolean) rVar2.c.a(c2601s72)).booleanValue();
                Lm lm = (Lm) this.b;
                if (zBooleanValue3) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, lm.g.d, "rendering-webview-creation-start");
                }
                Context context = lm.b;
                Vp vp2 = (Vp) this.d;
                com.google.android.gms.ads.internal.client.zzr zzrVarE = LA.e(context, vp2.u);
                C1849aq c1849aq2 = (C1849aq) this.c;
                final InterfaceC2529qe interfaceC2529qeA3 = lm.c.a(zzrVarE, vp2, (Xp) c1849aq2.b.b);
                interfaceC2529qeA3.D(vp2.W);
                C2601s7 c2601s73 = AbstractC2773w7.S7;
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u72 = rVar2.c;
                View viewA = (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(c2601s73)).booleanValue() && vp2.g0) ? ViewTreeObserverOnScrollChangedListenerC2057fg.a(context, interfaceC2529qeA3.N(), vp2) : new C2492pk(context, interfaceC2529qeA3.N(), (C1633i) lm.f.apply(vp2));
                boolean zBooleanValue4 = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(c2601s72)).booleanValue();
                Ek ek2 = lm.g;
                if (zBooleanValue4) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek2.d, "rendering-webview-creation-end");
                }
                C2326lq c2326lq2 = new C2326lq(c1849aq2, vp2, (String) null);
                com.google.firebase.messaging.u uVar = new com.google.firebase.messaging.u(viewA, interfaceC2529qeA3, new Km(interfaceC2529qeA3), zzrVarE.i ? new Wp(-3, 0, true) : new Wp(zzrVarE.e, zzrVarE.b, false));
                C1789Ve c1789Ve = lm.a;
                C1783Ue c1783Ue = new C1783Ue(c1789Ve.d, c1789Ve.e, c2326lq2, uVar);
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(c2601s72)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek2.d, "rendering-ad-component-creation-end");
                }
                BC bc2 = c1783Ue.Y;
                ((C2363mk) bc2.zzb()).a(interfaceC2529qeA3, false, null, ek2.d);
                C2146hh c2146hh = (C2146hh) c1783Ue.M.zzb();
                final int i2 = 1;
                InterfaceC2189ih interfaceC2189ih = new InterfaceC2189ih() { // from class: com.google.android.gms.internal.ads.Bm
                    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
                    public final void K() {
                        switch (i2) {
                            case 0:
                                InterfaceC2529qe interfaceC2529qe2 = interfaceC2529qeA3;
                                if (interfaceC2529qe2.L() != null) {
                                    interfaceC2529qe2.L().m0();
                                    break;
                                }
                                break;
                            case 1:
                                InterfaceC2529qe interfaceC2529qe3 = interfaceC2529qeA3;
                                if (interfaceC2529qe3.L() != null) {
                                    interfaceC2529qe3.L().m0();
                                    break;
                                }
                                break;
                            case 2:
                                InterfaceC2529qe interfaceC2529qe4 = interfaceC2529qeA3;
                                if (interfaceC2529qe4.L() != null) {
                                    interfaceC2529qe4.L().m0();
                                    break;
                                }
                                break;
                            default:
                                InterfaceC2529qe interfaceC2529qe5 = interfaceC2529qeA3;
                                if (interfaceC2529qe5.L() != null) {
                                    interfaceC2529qe5.L().m0();
                                    break;
                                }
                                break;
                        }
                    }
                };
                C2227jd c2227jd = AbstractC2270kd.g;
                c2146hh.i1(interfaceC2189ih, c2227jd);
                Yp yp2 = vp2.s;
                String strB2 = yp2.a;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.n5)).booleanValue() && ((C2622sm) c1783Ue.K.zzb()).c()) {
                    strB2 = AbstractC1675Ce.b(strB2, AbstractC1675Ce.a(vp2));
                }
                C2313ld c2313ldB = C2363mk.b(interfaceC2529qeA3, yp2.b, strB2, ek2.d);
                C1985dw c1985dw = c2313ldB.a;
                boolean z2 = vp2.M;
                Executor executor = lm.e;
                if (z2) {
                    c1985dw.a(new RunnableC1970dg(interfaceC2529qeA3, 5), executor);
                }
                c1985dw.a(new RunnableC2793wl(4, lm, interfaceC2529qeA3), executor);
                return AbstractC2025es.L(c2313ldB, new C1804Yb(c1783Ue, 2), c2227jd);
            case 5:
                return AbstractC2025es.E(ViewTreeObserverOnScrollChangedListenerC2057fg.a(((Gm) this.b).b, (View) this.c, (Vp) this.d));
            case 6:
                return AbstractC2025es.E(ViewTreeObserverOnScrollChangedListenerC2057fg.a(((Om) this.b).b, (View) this.c, (Vp) this.d));
            case 7:
                C2601s7 c2601s74 = AbstractC2773w7.k2;
                com.google.android.gms.ads.internal.client.r rVar3 = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue5 = ((Boolean) rVar3.c.a(c2601s74)).booleanValue();
                Um um = (Um) this.b;
                if (zBooleanValue5) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, um.j.d, "rendering-webview-creation-start");
                }
                C2406nk c2406nk2 = um.c;
                C1849aq c1849aq3 = (C1849aq) this.d;
                androidx.work.impl.model.n nVar2 = c1849aq3.b;
                C2023eq c2023eq2 = um.d;
                Vp vp3 = (Vp) this.c;
                final InterfaceC2529qe interfaceC2529qeA4 = c2406nk2.a(c2023eq2.e, vp3, (Xp) nVar2.b);
                interfaceC2529qeA4.D(vp3.W);
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u73 = rVar3.c;
                boolean zBooleanValue6 = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(c2601s74)).booleanValue();
                Ek ek3 = um.j;
                if (zBooleanValue6) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek3.d, "rendering-webview-creation-end");
                }
                C2313ld c2313ld3 = new C2313ld();
                C2326lq c2326lq3 = new C2326lq(c1849aq3, vp3, (String) null);
                VersionInfoParcel versionInfoParcel2 = um.f;
                C2475p9 c2475p93 = um.g;
                Context context2 = um.b;
                boolean z3 = um.h;
                Fi fi2 = new Fi(15, new Tm(context2, versionInfoParcel2, c2313ld3, vp3, interfaceC2529qeA4, c2023eq2, z3, c2475p93, um.i, um.k), interfaceC2529qeA4);
                C1813Ze c1813Ze = (C1813Ze) um.l;
                C1807Ye c1807Ye = new C1807Ye(c1813Ze.b, c1813Ze.c, c2326lq3, fi2);
                c2313ld3.c(c1807Ye);
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(c2601s74)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek3.d, "rendering-ad-component-creation-end");
                }
                final int i3 = 2;
                ((C2146hh) c1807Ye.H.zzb()).i1(new InterfaceC2189ih() { // from class: com.google.android.gms.internal.ads.Bm
                    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
                    public final void K() {
                        switch (i3) {
                            case 0:
                                InterfaceC2529qe interfaceC2529qe2 = interfaceC2529qeA4;
                                if (interfaceC2529qe2.L() != null) {
                                    interfaceC2529qe2.L().m0();
                                    break;
                                }
                                break;
                            case 1:
                                InterfaceC2529qe interfaceC2529qe3 = interfaceC2529qeA4;
                                if (interfaceC2529qe3.L() != null) {
                                    interfaceC2529qe3.L().m0();
                                    break;
                                }
                                break;
                            case 2:
                                InterfaceC2529qe interfaceC2529qe4 = interfaceC2529qeA4;
                                if (interfaceC2529qe4.L() != null) {
                                    interfaceC2529qe4.L().m0();
                                    break;
                                }
                                break;
                            default:
                                InterfaceC2529qe interfaceC2529qe5 = interfaceC2529qeA4;
                                if (interfaceC2529qe5.L() != null) {
                                    interfaceC2529qe5.L().m0();
                                    break;
                                }
                                break;
                        }
                    }
                }, AbstractC2270kd.g);
                Yp yp3 = vp3.s;
                String strB3 = yp3.a;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(AbstractC2773w7.n5)).booleanValue() && ((C2622sm) c1807Ye.G.zzb()).c()) {
                    strB3 = AbstractC1675Ce.b(strB3, AbstractC1675Ce.a(vp3));
                }
                BC bc3 = c1807Ye.X;
                C2363mk c2363mk2 = (C2363mk) bc3.zzb();
                if (true != z3) {
                    c2475p93 = null;
                }
                c2363mk2.a(interfaceC2529qeA4, true, c2475p93, ek3.d);
                return AbstractC2025es.L(C2363mk.b(interfaceC2529qeA4, yp3.b, strB3, ek3.d), new Jg(interfaceC2529qeA4, vp3, c1807Ye, 2), um.e);
            case 8:
                JSONArray jSONArray = (JSONArray) obj;
                if (jSONArray.length() == 0) {
                    return AbstractC2025es.C(new zzdwf(3));
                }
                C1849aq c1849aq4 = (C1849aq) this.c;
                C2023eq c2023eq3 = (C2023eq) c1849aq4.a.b;
                Vp vp4 = (Vp) this.d;
                int i4 = c2023eq3.k;
                Zm zm = (Zm) this.b;
                if (i4 <= 1) {
                    return AbstractC2025es.L(zm.c(c1849aq4, vp4, jSONArray.getJSONObject(0)), new C2853y1(9), zm.b);
                }
                int length = jSONArray.length();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.l2)).booleanValue()) {
                    zm.f.a("nsl", String.valueOf(length));
                }
                zm.d.b(Math.min(length, i4));
                ArrayList arrayList = new ArrayList(i4);
                for (int i5 = 0; i5 < i4; i5++) {
                    if (i5 < length) {
                        arrayList.add(zm.c(c1849aq4, vp4, jSONArray.getJSONObject(i5)));
                    } else {
                        arrayList.add(AbstractC2025es.C(new zzdwf(3)));
                    }
                }
                return AbstractC2025es.E(arrayList);
            default:
                C2601s7 c2601s75 = AbstractC2773w7.k2;
                com.google.android.gms.ads.internal.client.r rVar4 = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue7 = ((Boolean) rVar4.c.a(c2601s75)).booleanValue();
                Um um2 = (Um) this.b;
                if (zBooleanValue7) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, um2.j.d, "rendering-webview-creation-start");
                }
                C2406nk c2406nk3 = um2.c;
                C1849aq c1849aq5 = (C1849aq) this.d;
                androidx.work.impl.model.n nVar3 = c1849aq5.b;
                C2023eq c2023eq4 = um2.d;
                Vp vp5 = (Vp) this.c;
                final InterfaceC2529qe interfaceC2529qeA5 = c2406nk3.a(c2023eq4.e, vp5, (Xp) nVar3.b);
                interfaceC2529qeA5.D(vp5.W);
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u74 = rVar4.c;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u74.a(c2601s75)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, um2.j.d, "rendering-webview-creation-end");
                }
                C2313ld c2313ld4 = new C2313ld();
                C2326lq c2326lq4 = new C2326lq(c1849aq5, vp5, (String) null);
                VersionInfoParcel versionInfoParcel3 = um2.f;
                C2475p9 c2475p94 = um2.g;
                Context context3 = um2.b;
                boolean z4 = um2.h;
                BinderC2408nm binderC2408nm = um2.i;
                Ek ek4 = um2.j;
                C2149hk c2149hk = new C2149hk(new C2538qn(context3, c2406nk3, c2023eq4, versionInfoParcel3, vp5, c2313ld4, interfaceC2529qeA5, c2475p94, z4, binderC2408nm, ek4, um2.k), interfaceC2529qeA5, 0);
                C1882bf c1882bf = (C1882bf) um2.l;
                C1838af c1838af = new C1838af(c1882bf.c, c1882bf.d, c2326lq4, c2149hk);
                c2313ld4.c(c1838af);
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u74.a(c2601s75)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ek4.d, "rendering-ad-component-creation-end");
                }
                interfaceC2529qeA5.O0("/reward", new C1956d9((C2575ri) c1838af.W.zzb(), 4));
                final int i6 = 3;
                ((C2146hh) c1838af.H.zzb()).i1(new InterfaceC2189ih() { // from class: com.google.android.gms.internal.ads.Bm
                    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
                    public final void K() {
                        switch (i6) {
                            case 0:
                                InterfaceC2529qe interfaceC2529qe2 = interfaceC2529qeA5;
                                if (interfaceC2529qe2.L() != null) {
                                    interfaceC2529qe2.L().m0();
                                    break;
                                }
                                break;
                            case 1:
                                InterfaceC2529qe interfaceC2529qe3 = interfaceC2529qeA5;
                                if (interfaceC2529qe3.L() != null) {
                                    interfaceC2529qe3.L().m0();
                                    break;
                                }
                                break;
                            case 2:
                                InterfaceC2529qe interfaceC2529qe4 = interfaceC2529qeA5;
                                if (interfaceC2529qe4.L() != null) {
                                    interfaceC2529qe4.L().m0();
                                    break;
                                }
                                break;
                            default:
                                InterfaceC2529qe interfaceC2529qe5 = interfaceC2529qeA5;
                                if (interfaceC2529qe5.L() != null) {
                                    interfaceC2529qe5.L().m0();
                                    break;
                                }
                                break;
                        }
                    }
                }, AbstractC2270kd.g);
                BC bc4 = c1838af.X;
                ((C2363mk) bc4.zzb()).a(interfaceC2529qeA5, true, true != z4 ? null : c2475p94, ek4.d);
                Yp yp4 = vp5.s;
                String strB4 = yp4.a;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u74.a(AbstractC2773w7.n5)).booleanValue() && ((C2622sm) c1838af.G.zzb()).c()) {
                    strB4 = AbstractC1675Ce.b(strB4, AbstractC1675Ce.a(vp5));
                }
                return AbstractC2025es.L(C2363mk.b(interfaceC2529qeA5, yp4.b, strB4, ek4.d), new Jg(interfaceC2529qeA5, vp5, c1838af, 3), um2.e);
        }
    }

    public /* synthetic */ C2616sg(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }
}
