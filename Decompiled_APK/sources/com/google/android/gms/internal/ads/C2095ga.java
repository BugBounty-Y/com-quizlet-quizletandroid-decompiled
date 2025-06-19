package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.C1614q;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ga, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2095ga implements S9, InterfaceC2051fa {
    public final V9 a;
    public final HashSet b = new HashSet();

    public C2095ga(V9 v9) {
        this.a = v9;
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final /* synthetic */ void b(String str, JSONObject jSONObject) {
        AbstractC1972di.q(this, jSONObject);
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void d(String str, JSONObject jSONObject) {
        zzb(str, jSONObject.toString());
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final void j(String str, Map map) {
        try {
            b("openIntentAsync", C1614q.f.a.i((HashMap) map));
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not convert parameters to JSON.");
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2051fa
    public final void o(String str, InterfaceC2389n9 interfaceC2389n9) {
        this.a.o(str, interfaceC2389n9);
        this.b.remove(new AbstractMap.SimpleEntry(str, interfaceC2389n9));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2051fa
    public final void q(String str, InterfaceC2389n9 interfaceC2389n9) {
        this.a.q(str, interfaceC2389n9);
        this.b.add(new AbstractMap.SimpleEntry(str, interfaceC2389n9));
    }

    @Override // com.google.android.gms.internal.ads.S9, com.google.android.gms.internal.ads.W9
    public final void zza(String str) {
        this.a.zza(str);
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void zzb(String str, String str2) {
        zza(str + "(" + str2 + ");");
    }
}
