package com.google.android.gms.internal.ads;

import android.content.res.Resources;
import android.os.Bundle;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.quizlet.quizletandroid.R;
import java.util.concurrent.Callable;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class Aj implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ Aj(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws zzegy {
        Bundle bundle;
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.classmembership.c cVar = (com.quizlet.data.repository.classmembership.c) this.b;
                C1849aq c1849aq = (C1849aq) this.c;
                Vp vp = (Vp) this.d;
                JSONObject jSONObject = (JSONObject) this.e;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.o2)).booleanValue()) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ((Ek) cVar.d).d, "native-assets-loading-basic-start");
                }
                Yi yi = new Yi();
                int iOptInt = jSONObject.optInt("template_id", -1);
                synchronized (yi) {
                    yi.a = iOptInt;
                }
                String strOptString = jSONObject.optString("custom_template_id");
                synchronized (yi) {
                    yi.u = strOptString;
                }
                JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("omid_settings");
                String strOptString2 = jSONObjectOptJSONObject != null ? jSONObjectOptJSONObject.optString("omid_partner_name") : null;
                synchronized (yi) {
                    yi.y = strOptString2;
                }
                C2023eq c2023eq = (C2023eq) c1849aq.a.b;
                if (!c2023eq.g.contains(Integer.toString(yi.g()))) {
                    throw new zzegy(1, android.support.v4.media.session.a.f(yi.g(), "Invalid template ID: "));
                }
                if (yi.g() == 3) {
                    if (yi.a() == null) {
                        throw new zzegy(1, "No custom template id for custom template ad response.");
                    }
                    if (!c2023eq.h.contains(yi.a())) {
                        throw new zzegy(1, "Unexpected custom template id in the response.");
                    }
                }
                double dOptDouble = jSONObject.optDouble("rating", -1.0d);
                synchronized (yi) {
                    yi.r = dOptDouble;
                }
                String strOptString3 = jSONObject.optString("headline", null);
                if (vp.M) {
                    com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                    com.google.android.gms.ads.internal.util.F f = jVar.c;
                    Resources resourcesB = jVar.h.b();
                    strOptString3 = android.support.v4.media.session.a.l(resourcesB != null ? resourcesB.getString(R.string.s7) : "Test Ad", " : ", strOptString3);
                }
                yi.d("headline", strOptString3);
                yi.d("body", jSONObject.optString("body", null));
                yi.d("call_to_action", jSONObject.optString("call_to_action", null));
                yi.d("store", jSONObject.optString("store", null));
                yi.d("price", jSONObject.optString("price", null));
                yi.d("advertiser", jSONObject.optString("advertiser", null));
                return yi;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue() && (bundle = ((zzbvl) this.b).m) != null) {
                    AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "http-response-ready");
                }
                return new Sl((Vl) ((Iq) this.c).c.get(), (JSONObject) ((Iq) this.d).c.get(), (C1810Zb) ((Iq) this.e).c.get());
        }
    }
}
