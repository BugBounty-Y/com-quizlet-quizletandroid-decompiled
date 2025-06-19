package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Bk implements Jh, InterfaceC2617sh, InterfaceC1840ah, InterfaceC2618si {
    public final Ek a;
    public final Kk b;
    public final int c;

    public Bk(Ek ek, Kk kk, int i) {
        this.a = ek;
        this.b = kk;
        this.c = i;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
        Ek ek = this.a;
        ek.getClass();
        androidx.work.impl.model.n nVar = c1849aq.b;
        List list = (List) nVar.a;
        if (!list.isEmpty()) {
            int i = ((Vp) list.get(0)).b;
            ek.a("ad_format", Vp.a(i));
            if (i == 6) {
                ek.a.put("as", true != ek.b.g ? "0" : "1");
            }
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j2)).booleanValue()) {
            ek.a("mwl", Integer.toString(list.size()));
        }
        ek.a("gqi", ((Xp) nVar.b).b);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void a(String str) {
        C2601s7 c2601s7 = AbstractC2773w7.R6;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            boolean zBooleanValue = ((Boolean) rVar.c.a(AbstractC2773w7.x7)).booleanValue();
            Ek ek = this.a;
            if (zBooleanValue) {
                ek.a.put("sgw", String.valueOf(this.c));
            }
            ek.a.put("action", "sgf");
            ek.a("sgf_reason", str);
            this.b.b(ek.a, false);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void b(com.google.android.gms.ads.nonagon.signalgeneration.q qVar) {
        String str;
        C2601s7 c2601s7 = AbstractC2773w7.R6;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            C2601s7 c2601s72 = AbstractC2773w7.x7;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            boolean zBooleanValue = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue();
            Ek ek = this.a;
            if (zBooleanValue) {
                ek.a.put("sgw", String.valueOf(this.c));
            }
            Kk kk = this.b;
            if (qVar == null) {
                ek.a.put("action", "sgs");
                ConcurrentHashMap concurrentHashMap = ek.a;
                concurrentHashMap.put("request_id", "-1");
                kk.b(concurrentHashMap, false);
                return;
            }
            Bundle bundle = qVar.e;
            zzbvl zzbvlVar = qVar.d;
            if (zzbvlVar != null) {
                d(zzbvlVar.m, Dk.d);
            } else if (bundle != null && !bundle.isEmpty()) {
                d(bundle, Dk.d);
            }
            try {
                JSONObject jSONObject = new JSONObject(TextUtils.isEmpty(qVar.c) ? qVar.b : qVar.c);
                ek.a.put("action", "sgs");
                ConcurrentHashMap concurrentHashMap2 = ek.a;
                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.H9)).booleanValue()) {
                    try {
                        str = jSONObject.getJSONObject("extras").getBoolean("accept_3p_cookie") ? "1" : "0";
                    } catch (JSONException e) {
                        com.google.android.gms.ads.internal.util.client.i.f("Error retrieving JSONObject from the requestJson, ", e);
                    }
                } else {
                    str = "na";
                }
                concurrentHashMap2.put("tpc", str);
                if (zzbvlVar != null) {
                    ek.b(zzbvlVar.a);
                }
                kk.b(concurrentHashMap2, false);
            } catch (JSONException unused) {
                ek.a.put("action", "sgf");
                ConcurrentHashMap concurrentHashMap3 = ek.a;
                concurrentHashMap3.put("sgf_reason", "request_invalid");
                kk.b(concurrentHashMap3, false);
            }
        }
    }

    public final void c(Bundle bundle) {
        if (bundle == null) {
            return;
        }
        for (String str : bundle.keySet()) {
            long j = bundle.getLong(str);
            if (j >= 0) {
                this.a.a(str, String.valueOf(j));
            }
        }
    }

    public final void d(Bundle bundle, Bu bu) {
        C2601s7 c2601s7 = AbstractC2773w7.h2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue() || bundle == null) {
            return;
        }
        AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "public-api-callback");
        Ek ek = this.a;
        ek.getClass();
        if (((Boolean) rVar.c.a(AbstractC2773w7.id)).booleanValue()) {
            ek.a("brr", true != ek.c.p ? "0" : "1");
        }
        if (bundle.containsKey("ls")) {
            ek.a("ls", true != bundle.getBoolean("ls") ? "0" : "1");
        }
        int i = bu.d;
        for (int i2 = 0; i2 < i; i2++) {
            Dk dk = (Dk) bu.get(i2);
            long j = bundle.getLong(AbstractC1642h.b(dk.b), -1L);
            long j2 = bundle.getLong(AbstractC1642h.b(dk.c), -1L);
            if (j > 0 && j2 > 0) {
                ek.a(dk.a, String.valueOf(j2 - j));
            }
        }
        c(bundle.getBundle("client_sig_latency_key"));
        c(bundle.getBundle("gms_sig_latency_key"));
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.x7)).booleanValue()) {
            if (bundle.containsKey("sod_h")) {
                ek.a("sod_h", true != bundle.getBoolean("sod_h") ? "0" : "1");
            }
            if (bundle.containsKey("cmr")) {
                ek.a("cmr", String.valueOf(bundle.getInt("cmr")));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        Ek ek = this.a;
        ek.a.put("action", "ftl");
        ek.a("ftl", String.valueOf(zzeVar.a));
        ek.a("ed", zzeVar.c);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.f7)).booleanValue()) {
            ek.a("emsg", zzeVar.b);
        }
        this.b.b(ek.a, false);
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
        this.a.b(zzbvlVar.a);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        Ek ek = this.a;
        ek.a.put("action", "loaded");
        d(ek.d, Dk.e);
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Cc)).booleanValue();
        ConcurrentHashMap concurrentHashMap = ek.a;
        if (zBooleanValue) {
            concurrentHashMap.put("mafe", true != AbstractC3379p2.c("MUTE_AUDIO") ? "0" : "1");
        }
        this.b.b(concurrentHashMap, false);
    }
}
