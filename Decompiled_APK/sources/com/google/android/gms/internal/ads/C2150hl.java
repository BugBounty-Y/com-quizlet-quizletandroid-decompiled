package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzv;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.hl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2150hl implements InterfaceC1840ah, Jh, InterfaceC2703uh {
    public final C2493pl a;
    public final String b;
    public final String c;
    public Ug f;
    public zze g;
    public JSONObject k;
    public JSONObject l;
    public boolean m;
    public boolean n;
    public boolean o;
    public String h = "";
    public String i = "";
    public String j = "";
    public int d = 0;
    public EnumC2106gl e = EnumC2106gl.a;

    public C2150hl(C2493pl c2493pl, C2023eq c2023eq, String str) {
        this.a = c2493pl;
        this.c = str;
        this.b = c2023eq.f;
    }

    public static JSONObject b(zze zzeVar) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("errorDomain", zzeVar.c);
        jSONObject.put("errorCode", zzeVar.a);
        jSONObject.put("errorDescription", zzeVar.b);
        zze zzeVar2 = zzeVar.d;
        jSONObject.put("underlyingError", zzeVar2 == null ? null : b(zzeVar2));
        return jSONObject;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
        C2493pl c2493pl = this.a;
        if (c2493pl.f()) {
            androidx.work.impl.model.n nVar = c1849aq.b;
            List list = (List) nVar.a;
            if (!list.isEmpty()) {
                this.d = ((Vp) list.get(0)).b;
            }
            Xp xp = (Xp) nVar.b;
            String str = xp.l;
            if (!TextUtils.isEmpty(str)) {
                this.h = str;
            }
            String str2 = xp.m;
            if (!TextUtils.isEmpty(str2)) {
                this.i = str2;
            }
            JSONObject jSONObject = xp.p;
            if (jSONObject.length() > 0) {
                this.l = jSONObject;
            }
            C2601s7 c2601s7 = AbstractC2773w7.o9;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                if (c2493pl.w >= ((Long) rVar.c.a(AbstractC2773w7.p9)).longValue()) {
                    this.o = true;
                    return;
                }
                String str3 = xp.n;
                if (!TextUtils.isEmpty(str3)) {
                    this.j = str3;
                }
                JSONObject jSONObject2 = xp.o;
                if (jSONObject2.length() > 0) {
                    this.k = jSONObject2;
                }
                JSONObject jSONObject3 = this.k;
                int length = jSONObject3 != null ? jSONObject3.toString().length() : 0;
                if (!TextUtils.isEmpty(this.j)) {
                    length += this.j.length();
                }
                long j = length;
                synchronized (c2493pl) {
                    c2493pl.w += j;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2703uh
    public final void M(AbstractC2359mg abstractC2359mg) {
        C2493pl c2493pl = this.a;
        if (c2493pl.f()) {
            this.f = abstractC2359mg.f;
            this.e = EnumC2106gl.b;
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s9)).booleanValue()) {
                c2493pl.b(this.b, this);
            }
        }
    }

    public final JSONObject a() throws JSONException {
        JSONObject jSONObjectC;
        IBinder iBinder;
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("state", this.e);
        jSONObject.put("format", Vp.a(this.d));
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s9)).booleanValue()) {
            jSONObject.put("isOutOfContext", this.m);
            if (this.m) {
                jSONObject.put("shown", this.n);
            }
        }
        Ug ug = this.f;
        if (ug != null) {
            jSONObjectC = c(ug);
        } else {
            zze zzeVar = this.g;
            JSONObject jSONObjectC2 = null;
            if (zzeVar != null && (iBinder = zzeVar.e) != null) {
                Ug ug2 = (Ug) iBinder;
                jSONObjectC2 = c(ug2);
                if (ug2.e.isEmpty()) {
                    JSONArray jSONArray = new JSONArray();
                    jSONArray.put(b(this.g));
                    jSONObjectC2.put("errors", jSONArray);
                }
            }
            jSONObjectC = jSONObjectC2;
        }
        jSONObject.put("responseInfo", jSONObjectC);
        return jSONObject;
    }

    public final JSONObject c(Ug ug) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("winningAdapterClassName", ug.a);
        jSONObject.put("responseSecsSinceEpoch", ug.f);
        jSONObject.put("responseId", ug.b);
        C2601s7 c2601s7 = AbstractC2773w7.l9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            String str = ug.g;
            if (!TextUtils.isEmpty(str)) {
                com.google.android.gms.ads.internal.util.client.i.d("Bidding data: ".concat(String.valueOf(str)));
                jSONObject.put("biddingData", new JSONObject(str));
            }
        }
        if (!TextUtils.isEmpty(this.h)) {
            jSONObject.put("adRequestUrl", this.h);
        }
        if (!TextUtils.isEmpty(this.i)) {
            jSONObject.put("postBody", this.i);
        }
        if (!TextUtils.isEmpty(this.j)) {
            jSONObject.put("adResponseBody", this.j);
        }
        Object obj = this.k;
        if (obj != null) {
            jSONObject.put("adResponseHeaders", obj);
        }
        Object obj2 = this.l;
        if (obj2 != null) {
            jSONObject.put("transactionExtras", obj2);
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.o9)).booleanValue()) {
            jSONObject.put("hasExceededMemoryLimit", this.o);
        }
        JSONArray jSONArray = new JSONArray();
        for (zzv zzvVar : ug.e) {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("adapterClassName", zzvVar.a);
            jSONObject2.put("latencyMillis", zzvVar.b);
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.m9)).booleanValue()) {
                jSONObject2.put("credentials", C1614q.f.a.h(zzvVar.d));
            }
            zze zzeVar = zzvVar.c;
            jSONObject2.put("error", zzeVar == null ? null : b(zzeVar));
            jSONArray.put(jSONObject2);
        }
        jSONObject.put("adNetworks", jSONArray);
        return jSONObject;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        C2493pl c2493pl = this.a;
        if (c2493pl.f()) {
            this.e = EnumC2106gl.c;
            this.g = zzeVar;
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s9)).booleanValue()) {
                c2493pl.b(this.b, this);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s9)).booleanValue()) {
            return;
        }
        C2493pl c2493pl = this.a;
        if (c2493pl.f()) {
            c2493pl.b(this.b, this);
        }
    }
}
