package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.AdRequest$Builder;
import java.util.Date;
import java.util.concurrent.ScheduledExecutorService;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class I7 {
    public final ScheduledExecutorService a;
    public final com.google.android.gms.ads.nonagon.signalgeneration.A b;
    public final com.google.android.gms.ads.nonagon.signalgeneration.v c;
    public final Kk d;
    public RunnableC1989e e;
    public H7 f;
    public androidx.work.impl.model.n g;
    public String h;
    public long i = 0;
    public long j;
    public JSONArray k;
    public Context l;

    public I7(ScheduledExecutorService scheduledExecutorService, com.google.android.gms.ads.nonagon.signalgeneration.A a, com.google.android.gms.ads.nonagon.signalgeneration.v vVar, Kk kk) {
        this.a = scheduledExecutorService;
        this.b = a;
        this.c = vVar;
        this.d = kk;
    }

    public final JSONObject a(String str, String str2) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("paw_id", str);
        jSONObject.put("error", str2);
        jSONObject.put("sdk_ttl_ms", ((Boolean) AbstractC1911c8.e.o()).booleanValue() ? ((Long) AbstractC1911c8.h.o()).longValue() : 0L);
        e(jSONObject);
        if (((Boolean) AbstractC1911c8.c.o()).booleanValue()) {
            jSONObject.put("as", this.c.a());
        }
        return jSONObject;
    }

    public final JSONObject b(String str, String str2) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("paw_id", str);
        jSONObject.put("signal", str2);
        jSONObject.put("sdk_ttl_ms", ((Boolean) AbstractC1911c8.e.o()).booleanValue() ? ((Long) AbstractC1911c8.h.o()).longValue() : 0L);
        e(jSONObject);
        if (((Boolean) AbstractC1911c8.c.o()).booleanValue()) {
            jSONObject.put("as", this.c.a());
        }
        return jSONObject;
    }

    public final void c(String str) throws JSONException {
        try {
            androidx.work.impl.model.n nVar = this.g;
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("gsppack", true);
            jSONObject.put("fpt", new Date(this.j).toString());
            e(jSONObject);
            if (((Boolean) AbstractC1911c8.c.o()).booleanValue()) {
                jSONObject.put("as", this.c.a());
            }
            nVar.h(jSONObject.toString());
            com.google.android.gms.ads.nonagon.signalgeneration.s sVar = new com.google.android.gms.ads.nonagon.signalgeneration.s(str, 1, this);
            if (((Boolean) AbstractC1911c8.e.o()).booleanValue()) {
                this.b.b(this.g, sVar);
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putString("query_info_type", "requester_type_6");
            Context context = this.l;
            AdRequest$Builder adRequest$Builder = (AdRequest$Builder) new AdRequest$Builder().addNetworkExtrasBundle(AdMobAdapter.class, bundle);
            adRequest$Builder.getClass();
            androidx.appcompat.app.L.J(context, new com.google.android.gms.ads.g(adRequest$Builder), sVar);
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error creating JSON: ", e);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x004a, code lost:
    
        if (((java.lang.Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(com.google.android.gms.internal.ads.AbstractC2773w7.R9)).booleanValue() != false) goto L23;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d() {
        /*
            r6 = this;
            com.google.android.gms.internal.ads.H7 r0 = r6.f
            if (r0 != 0) goto La
            java.lang.String r0 = "PACT callback is not present, please initialize the PawCustomTabsImpl."
            com.google.android.gms.ads.internal.util.client.i.e(r0)
            return
        La:
            java.util.concurrent.atomic.AtomicBoolean r0 = r0.a
            boolean r0 = r0.get()
            if (r0 == 0) goto L13
            return
        L13:
            java.lang.String r0 = r6.h
            if (r0 == 0) goto L98
            androidx.work.impl.model.n r0 = r6.g
            if (r0 == 0) goto L98
            java.util.concurrent.ScheduledExecutorService r0 = r6.a
            if (r0 == 0) goto L98
            long r1 = r6.i
            r3 = 0
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 != 0) goto L28
            goto L3a
        L28:
            com.google.android.gms.ads.internal.j r1 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.common.util.b r1 = r1.k
            r1.getClass()
            long r1 = android.os.SystemClock.elapsedRealtime()
            long r3 = r6.i
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 > 0) goto L3a
            goto L4c
        L3a:
            com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.R9
            com.google.android.gms.ads.internal.client.r r2 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r2 = r2.c
            java.lang.Object r1 = r2.a(r1)
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 == 0) goto L98
        L4c:
            androidx.work.impl.model.n r1 = r6.g
            java.lang.String r2 = r6.h
            android.net.Uri r2 = android.net.Uri.parse(r2)
            r1.getClass()
            android.os.Bundle r3 = new android.os.Bundle
            r3.<init>()
            android.os.Bundle r4 = new android.os.Bundle     // Catch: android.os.RemoteException -> L80
            r4.<init>()     // Catch: android.os.RemoteException -> L80
            boolean r5 = r4.isEmpty()     // Catch: android.os.RemoteException -> L80
            if (r5 == 0) goto L68
            r4 = 0
        L68:
            java.lang.Object r5 = r1.c
            androidx.browser.customtabs.g r5 = (androidx.browser.customtabs.g) r5
            java.lang.Object r1 = r1.b
            android.support.customtabs.d r1 = (android.support.customtabs.d) r1
            if (r4 == 0) goto L7b
            r3.putAll(r4)     // Catch: android.os.RemoteException -> L80
            android.support.customtabs.b r1 = (android.support.customtabs.b) r1     // Catch: android.os.RemoteException -> L80
            r1.f3(r5, r2, r3)     // Catch: android.os.RemoteException -> L80
            goto L80
        L7b:
            android.support.customtabs.b r1 = (android.support.customtabs.b) r1     // Catch: android.os.RemoteException -> L80
            r1.L2(r5, r2)     // Catch: android.os.RemoteException -> L80
        L80:
            com.google.android.gms.internal.ads.e r1 = r6.e
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.S9
            com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r3 = r3.c
            java.lang.Object r2 = r3.a(r2)
            java.lang.Long r2 = (java.lang.Long) r2
            long r2 = r2.longValue()
            java.util.concurrent.TimeUnit r4 = java.util.concurrent.TimeUnit.MILLISECONDS
            r0.schedule(r1, r2, r4)
            return
        L98:
            java.lang.String r0 = "PACT max retry connection duration timed out"
            com.google.android.gms.ads.internal.util.A.l(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.I7.d():void");
    }

    public final void e(JSONObject jSONObject) throws JSONException {
        try {
            if (this.k == null) {
                this.k = new JSONArray((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U9));
            }
            jSONObject.put("eids", this.k);
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error fetching the PACT active eids JSON: ", e);
        }
    }
}
