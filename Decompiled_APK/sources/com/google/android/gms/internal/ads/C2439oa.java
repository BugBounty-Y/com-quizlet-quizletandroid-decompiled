package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeoutException;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.oa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2439oa implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C2439oa(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) throws JSONException, zzboc {
        zzegy zzegyVar;
        int i = 21;
        C2755vq c2755vq = null;
        int i2 = 4;
        int i3 = 0;
        switch (this.a) {
            case 0:
                InterfaceC2051fa interfaceC2051fa = (InterfaceC2051fa) obj;
                interfaceC2051fa.q((String) this.b, (InterfaceC2389n9) this.c);
                return AbstractC2025es.E(interfaceC2051fa);
            case 1:
                C2313ld c2313ld = new C2313ld();
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                String string = UUID.randomUUID().toString();
                AbstractC2346m9.o.a(string, new C2732v9(c2313ld, 1));
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("id", string);
                jSONObject.put("args", (JSONObject) this.c);
                ((C2525qa) this.b).getClass();
                ((InterfaceC2051fa) obj).d("google.afma.activeView.handleUpdate", jSONObject);
                return c2313ld;
            case 2:
                C2830xf c2830xf = (C2830xf) this.b;
                c2830xf.e.a(new RunnableC2787wf(c2830xf, (Throwable) obj, 0));
                String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ja);
                Uri.Builder builder = (Uri.Builder) this.c;
                builder.appendQueryParameter(str, "9");
                return AbstractC2025es.E(builder.toString());
            case 3:
                zzbvl zzbvlVar = (zzbvl) obj;
                zzbvlVar.i = (zzfej) this.c;
                C2326lq c2326lq = ((C2831xg) this.b).h;
                return c2326lq.A(zzbvlVar, new S4((Jl) c2326lq.c, 20), new C2881yn(c2326lq, i), new C2879yl(zzbvlVar, 2));
            case 4:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                Oj oj = (Oj) this.b;
                C2023eq c2023eq = oj.a;
                C2257k6 c2257k6 = new C2257k6(interfaceC2529qe);
                if (c2023eq.b != null) {
                    interfaceC2529qe.k0(new com.bumptech.glide.load.engine.cache.f(5, 0, 0));
                } else {
                    interfaceC2529qe.k0(new com.bumptech.glide.load.engine.cache.f(4, 0, 0));
                }
                interfaceC2529qe.L().g = new Kj(oj, interfaceC2529qe, c2257k6, 1);
                interfaceC2529qe.d("google.afma.nativeAds.renderVideo", (JSONObject) this.c);
                return c2257k6;
            case 5:
                JSONObject jSONObject2 = (JSONObject) obj;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j2)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ((Dl) this.b).i.d, "scar-preloader-processing-done");
                }
                return ((com.google.android.gms.ads.internal.c) this.c).a(jSONObject2);
            case 6:
                Exception exc = (Exception) obj;
                com.google.android.gms.ads.internal.j.C.h.g("PreloadedLoader.getTypeTwoAdResponseString", exc);
                if (exc instanceof TimeoutException) {
                    zzegyVar = new zzegy(1, "Timed out waiting for ad response.");
                } else if (exc instanceof zzegy) {
                    zzegyVar = (zzegy) exc;
                } else {
                    zzegyVar = new zzegy(1, exc.getMessage() == null ? "Fetch failed." : exc.getMessage());
                }
                String message = zzegyVar.getMessage() == null ? "" : zzegyVar.getMessage();
                List list = (List) this.c;
                if (list != null && !list.isEmpty()) {
                    String str2 = "0.6.0.0";
                    if (!TextUtils.isEmpty(message)) {
                        if (message.contains("Timed out waiting for ad response.")) {
                            message = "timeout";
                            str2 = "0.2.0.0";
                        } else if (message.contains("Received HTTP error code from ad server:")) {
                            List listK = C2883yp.e(new C2501pt(':')).k(message);
                            if (listK.size() == 2) {
                                message = (String) listK.get(1);
                            }
                        }
                    }
                    ArrayList arrayList = new ArrayList();
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        arrayList.add(C2542qr.a(C2542qr.a((String) it2.next(), "@gw_adnetstatus@", str2), "@error_code@", message));
                    }
                    ((Dl) this.b).j.b(arrayList, null);
                }
                return AbstractC2025es.C(zzegyVar);
            case 7:
                return ((Ml) ((HC) this.b).zzb()).a((zzbvl) this.c);
            case 8:
                Bundle bundle = (Bundle) obj;
                androidx.work.impl.model.n nVar = (androidx.work.impl.model.n) this.b;
                C1765Re c1765Re = (C1765Re) nVar.b;
                Context context = c1765Re.a.b;
                AbstractC1981ds.s(context);
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                com.android.billingclient.api.s sVar = (com.android.billingclient.api.s) nVar.a;
                zzbvl zzbvlVar2 = (zzbvl) sVar.c;
                AbstractC1981ds.s(zzbvlVar2.d);
                C2197ip c2197ip = new C2197ip();
                BC bc = c1765Re.d;
                Io io2 = new Io(c2197ip, 0L, (ScheduledExecutorService) bc.zzb());
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) bc.zzb();
                Context context2 = c1765Re.a.b;
                AbstractC1981ds.s(context2);
                Io io3 = new Io(new Un(scheduledExecutorService, 6), ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.l4)).longValue(), (ScheduledExecutorService) bc.zzb());
                L9 l9 = new L9(18);
                AbstractC1981ds.s(context2);
                Io io4 = new Io(new C2022ep(l9, context2, (ScheduledExecutorService) bc.zzb(), c2227jd, sVar.b, zzbvlVar2.l, zzbvlVar2.k), 0L, (ScheduledExecutorService) bc.zzb());
                Io io5 = new Io(new C2839xo(c2227jd, 4), 0L, (ScheduledExecutorService) bc.zzb());
                C2839xo c2839xo = new C2839xo(c2227jd, 3);
                AbstractC1981ds.s(c2227jd);
                ArrayList arrayList2 = ((zzbvl) sVar.c).e;
                AbstractC1981ds.s(arrayList2);
                Yn yn = new Yn(7, c2227jd, arrayList2);
                nVar.getClass();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                zzbvl zzbvlVar3 = (zzbvl) ((com.android.billingclient.api.s) nVar.a).c;
                String string2 = zzbvlVar3.a.getString("ms");
                if (string2 == null) {
                    string2 = "";
                }
                PackageInfo packageInfo = zzbvlVar3.f;
                Yn yn2 = new Yn(6, c2227jd2, string2);
                Vo vo = (Vo) c1765Re.K0.zzb();
                AbstractC1981ds.s(zzbvlVar2.d);
                Vo[] voArr = {yn2, vo, new C2021eo((C2010ed) c1765Re.O.zzb(), (ScheduledExecutorService) bc.zzb(), c2227jd)};
                int i4 = AbstractC2459ou.c;
                Object[] objArr = new Object[9];
                objArr[0] = io2;
                objArr[1] = io3;
                objArr[2] = io4;
                objArr[3] = io5;
                objArr[4] = c2839xo;
                objArr[5] = yn;
                System.arraycopy(voArr, 0, objArr, 6, 3);
                return new Xo(context, c2227jd, AbstractC2459ou.o(9, objArr), (Tq) ((BC) nVar.c).zzb(), (Hk) c1765Re.x.zzb()).a(C1614q.f.a.h(bundle), ((zzbvl) this.c).m, false);
            case 9:
                return ((Xo) this.b).a(C1614q.f.a.h((Bundle) obj), ((zzbvl) this.c).m, false);
            case 10:
                JSONObject jSONObject3 = (JSONObject) obj;
                Zm zm = (Zm) this.b;
                C2412nq c2412nq = zm.d;
                Tv tvE = AbstractC2025es.E((C1843ak) this.c);
                synchronized (c2412nq) {
                    c2412nq.a.addFirst(tvE);
                }
                if (!jSONObject3.optBoolean("success")) {
                    throw new zzboc("process json failed");
                }
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j2)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, zm.f.d, "rendering-native-ads-preprocess-end");
                }
                return AbstractC2025es.E(jSONObject3.getJSONObject("json").getJSONArray("ads"));
            case 11:
                C1843ak c1843ak = (C1843ak) obj;
                C2601s7 c2601s7 = AbstractC2773w7.j2;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
                Zm zm2 = (Zm) this.b;
                if (zBooleanValue) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, zm2.f.d, "rendering-native-ads-preprocess-start");
                }
                JSONObject jSONObject4 = new JSONObject();
                jSONObject4.put("isNonagon", true);
                if (((Boolean) rVar.c.a(AbstractC2773w7.H8)).booleanValue() && com.google.android.gms.common.util.c.j()) {
                    jSONObject4.put("skipDeepLinkValidation", true);
                }
                JSONObject jSONObject5 = new JSONObject();
                jSONObject5.put("response", ((Vp) this.c).s.c);
                jSONObject5.put("sdk_params", jSONObject4);
                return AbstractC2025es.N(c1843ak.a("google.afma.nativeAds.preProcessJson", jSONObject5), new C2439oa(10, zm2, c1843ak), zm2.b);
            case 12:
                C1849aq c1849aq = (C1849aq) obj;
                ((C2755vq) this.b).b = c1849aq;
                Iterator it3 = ((List) c1849aq.b.a).iterator();
                while (true) {
                    if (it3.hasNext()) {
                        Iterator it4 = ((Vp) it3.next()).a.iterator();
                        while (it4.hasNext()) {
                            if (((String) it4.next()).contains("FirstPartyRenderer")) {
                                i3 = 1;
                            }
                        }
                    } else if (i3 != 0) {
                        return ((C2831xg) this.c).a(AbstractC2025es.E(c1849aq));
                    }
                }
                return Tv.b;
            default:
                C2326lq c2326lq2 = (C2326lq) this.b;
                Qg qg = (Qg) this.c;
                Ap ap = (Ap) obj;
                C2326lq c2326lq3 = (C2326lq) c2326lq2.b;
                InterfaceC2798wq interfaceC2798wq = ap.b;
                zzbvl zzbvlVar4 = ap.a;
                synchronized (c2326lq3) {
                    try {
                        C2583rq c2583rq = (C2583rq) ((ConcurrentHashMap) c2326lq3.b).get(interfaceC2798wq);
                        if (c2583rq != null) {
                            Eq eq = c2583rq.d;
                            eq.getClass();
                            com.google.android.gms.ads.internal.j.C.k.getClass();
                            eq.c = System.currentTimeMillis();
                            eq.d++;
                            c2583rq.a();
                            LinkedList linkedList = c2583rq.a;
                            if (!linkedList.isEmpty() && (c2755vq = (C2755vq) linkedList.remove()) != null) {
                                eq.e++;
                                eq.b.a = true;
                            }
                            if (c2755vq == null) {
                                ((C2669tq) c2326lq3.d).e++;
                            }
                            Cq cq = c2583rq.d.b;
                            Cq cqClone = cq.clone();
                            cq.a = false;
                            cq.b = 0;
                            if (c2755vq != null) {
                                O6 o6W = T6.w();
                                M6 m6Z = N6.z();
                                m6Z.e();
                                N6.w((N6) m6Z.b);
                                P6 p6W = Q6.w();
                                boolean z = cqClone.a;
                                p6W.e();
                                Q6.y((Q6) p6W.b, z);
                                int i5 = cqClone.b;
                                p6W.e();
                                Q6.z((Q6) p6W.b, i5);
                                m6Z.e();
                                N6.x((N6) m6Z.b, (Q6) p6W.c());
                                o6W.e();
                                T6.x((T6) o6W.b, (N6) m6Z.c());
                                c2755vq.a.zzb().f.z0((T6) o6W.c());
                            }
                            c2326lq3.y();
                        } else {
                            ((C2669tq) c2326lq3.d).d++;
                            c2326lq3.y();
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                if (c2755vq != null && zzbvlVar4 != null) {
                    C2831xg c2831xgZzb = qg.zzb();
                    Jq jq = Jq.NOTIFY_CACHE_HIT;
                    C2326lq c2326lq4 = c2831xgZzb.h;
                    Iq iqB = c2831xgZzb.c.a(c2326lq4.A(zzbvlVar4, new Os(c2326lq4, i), new Ts(c2326lq4, 23), new C2487pf(i2)), jq).b();
                    iqB.a(new Qv(i3, iqB, new C2881yn(c2831xgZzb, 12)), c2831xgZzb.j);
                    iqB.a(new Qv(i3, iqB, (C2147hi) c2326lq2.d), (Xv) c2326lq2.c);
                }
                return AbstractC2025es.E(new C2797wp(interfaceC2798wq, zzbvlVar4, c2755vq));
        }
    }
}
