package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.Parcel;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class D9 implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ D9(Or or, Os os) {
        this.a = 13;
        this.b = or;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) throws JSONException, zzdwf {
        int length;
        C2134hC c2134hC;
        C2889yv c2889yvL;
        C2755vq c2755vq;
        C2711up c2711up;
        switch (this.a) {
            case 0:
                B9 b9 = (B9) obj;
                C2313ld c2313ld = new C2313ld();
                C9 c9 = new C9(c2313ld);
                Parcel parcelF3 = b9.f3();
                AbstractC2857y5.c(parcelF3, (zzblh) this.b);
                AbstractC2857y5.e(parcelF3, c9);
                b9.e4(2, parcelF3);
                return c2313ld;
            case 1:
                C1673Cc c1673Cc = (C1673Cc) this.b;
                Map map = (Map) obj;
                if (map != null) {
                    try {
                        for (String str : map.keySet()) {
                            JSONArray jSONArrayOptJSONArray = new JSONObject((String) map.get(str)).optJSONArray("matches");
                            if (jSONArrayOptJSONArray != null) {
                                Object obj2 = c1673Cc.h;
                                synchronized (obj2) {
                                    try {
                                        length = jSONArrayOptJSONArray.length();
                                        synchronized (obj2) {
                                            c2134hC = (C2134hC) c1673Cc.b.get(str);
                                        }
                                    } finally {
                                    }
                                }
                                if (c2134hC == null) {
                                    AbstractC2096gb.i("Cannot find the corresponding resource object for " + str);
                                } else {
                                    for (int i = 0; i < length; i++) {
                                        String string = jSONArrayOptJSONArray.getJSONObject(i).getString("threat_type");
                                        c2134hC.e();
                                        C2178iC.z((C2178iC) c2134hC.b, string);
                                    }
                                    c1673Cc.f = (length > 0) | c1673Cc.f;
                                }
                            }
                        }
                    } catch (JSONException unused) {
                        if (((Boolean) AbstractC2042f8.a.o()).booleanValue()) {
                            com.google.android.gms.ads.internal.util.client.i.k(3);
                        }
                        return AbstractC2025es.C(new Exception("Safebrowsing report transmission failed."));
                    }
                }
                if (c1673Cc.f) {
                    synchronized (c1673Cc.h) {
                        KB kb = c1673Cc.a;
                        kb.e();
                        C2392nC.K((C2392nC) kb.b, 10);
                    }
                }
                boolean z = c1673Cc.f;
                if (!(z && c1673Cc.g.g) && (!(c1673Cc.k && c1673Cc.g.f) && (z || !c1673Cc.g.d))) {
                    return Tv.b;
                }
                synchronized (c1673Cc.h) {
                    try {
                        for (C2134hC c2134hC2 : c1673Cc.b.values()) {
                            KB kb2 = c1673Cc.a;
                            C2178iC c2178iC = (C2178iC) c2134hC2.c();
                            kb2.e();
                            C2392nC.C((C2392nC) kb2.b, c2178iC);
                        }
                        KB kb3 = c1673Cc.a;
                        ArrayList arrayList = c1673Cc.c;
                        kb3.e();
                        C2392nC.A((C2392nC) kb3.b, arrayList);
                        ArrayList arrayList2 = c1673Cc.d;
                        kb3.e();
                        C2392nC.B((C2392nC) kb3.b, arrayList2);
                        if (((Boolean) AbstractC2042f8.a.o()).booleanValue()) {
                            StringBuilder sb = new StringBuilder("Sending SB report\n  url: " + ((C2392nC) kb3.b).y() + "\n  clickUrl: " + ((C2392nC) kb3.b).x() + "\n  resources: \n");
                            for (C2178iC c2178iC2 : Collections.unmodifiableList(((C2392nC) kb3.b).z())) {
                                sb.append("    [");
                                sb.append(c2178iC2.w());
                                sb.append("] ");
                                sb.append(c2178iC2.y());
                            }
                            AbstractC2096gb.i(sb.toString());
                        }
                        byte[] bArrD = ((C2392nC) kb3.c()).d();
                        String str2 = c1673Cc.g.b;
                        new com.google.android.gms.ads.internal.util.q(c1673Cc.e);
                        com.google.android.gms.ads.internal.util.o oVarA = com.google.android.gms.ads.internal.util.q.a(1, str2, null, bArrD);
                        if (((Boolean) AbstractC2042f8.a.o()).booleanValue()) {
                            oVarA.a.a(new C4(1), AbstractC2270kd.a);
                        }
                        c2889yvL = AbstractC2025es.L(oVarA, new C2853y1(3), AbstractC2270kd.g);
                    } finally {
                    }
                }
                return c2889yvL;
            case 2:
                String str3 = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ja);
                Uri.Builder builder = (Uri.Builder) this.b;
                builder.appendQueryParameter(str3, "12");
                return AbstractC2025es.E(builder.toString());
            case 3:
                ((com.quizlet.remote.model.notes.e) this.b).zza((Throwable) obj);
                return Tv.b;
            case 4:
                return ((Ll) this.b).a((zzbvl) obj);
            case 5:
                return obj != null ? (C2889yv) this.b : AbstractC2025es.C(new zzegy(1, "Retrieve required value in native ad response failed."));
            case 6:
                Nl nl = (Nl) obj;
                return AbstractC2025es.E(new C1849aq(new S4(((Cl) this.b).c, 26), androidx.work.impl.model.n.j(new InputStreamReader(nl.a), nl.b.m)));
            case 7:
                String str4 = (String) obj;
                JSONObject jSONObject = new JSONObject();
                JSONObject jSONObject2 = new JSONObject();
                JSONObject jSONObject3 = new JSONObject();
                String str5 = (String) this.b;
                try {
                    jSONObject3.put("headers", new JSONObject());
                    jSONObject3.put("body", str4);
                    jSONObject2.put("base_url", "");
                    jSONObject2.put("signals", new JSONObject(str5));
                    jSONObject.put("request", jSONObject2);
                    jSONObject.put("response", jSONObject3);
                    jSONObject.put("flags", new JSONObject());
                    return AbstractC2025es.E(jSONObject);
                } catch (JSONException e) {
                    throw new JSONException("Preloaded loader: ".concat(String.valueOf(e.getCause())));
                }
            case 8:
                Dl dl = (Dl) this.b;
                return AbstractC2025es.E(new C1849aq(new S4(dl.d, 26), androidx.work.impl.model.n.j(new StringReader(((JSONObject) obj).toString()), dl.o)));
            case 9:
                Throwable th = (Throwable) obj;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.q2)).booleanValue()) {
                    Vo vo = ((Io) this.b).a;
                    com.google.android.gms.ads.internal.j.C.h.h("OptionalSignalTimeout:" + vo.zza(), th);
                }
                return Tv.b;
            case 10:
                Throwable th2 = (Throwable) obj;
                ((C1935cp) this.b).c.a(new RunnableC2104gj(th2, 9));
                return AbstractC2025es.E(th2 instanceof SecurityException ? new C2453oo("", 2, 2) : th2 instanceof IllegalStateException ? new C2453oo("", 3, 2) : th2 instanceof IllegalArgumentException ? new C2453oo("", 4, 2) : th2 instanceof TimeoutException ? new C2453oo("", 5, 2) : new C2453oo("", 0, 2));
            case 11:
                return AbstractC2025es.E(new C1934co((String) ((Yn) this.b).c, 4));
            case 12:
                Bq bq = (Bq) obj;
                if (bq == null || (c2755vq = bq.a) == null || (c2711up = bq.b) == null) {
                    throw new zzdwf(1, "Empty prefetch");
                }
                O6 o6W = T6.w();
                M6 m6Z = N6.z();
                m6Z.e();
                N6.w((N6) m6Z.b);
                Q6 q6X = Q6.x();
                m6Z.e();
                N6.x((N6) m6Z.b, q6X);
                o6W.e();
                T6.x((T6) o6W.b, (N6) m6Z.c());
                c2755vq.a.zzb().f.r((T6) o6W.c());
                return ((C2084g6) this.b).o(c2755vq, c2711up.b);
            case 13:
                Or or = (Or) this.b;
                Exception exc = (Exception) obj;
                synchronized (or) {
                    or.b = true;
                    throw exc;
                }
            default:
                return AbstractC2025es.E(((Gq) this.b).b(obj));
        }
    }

    public /* synthetic */ D9(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
