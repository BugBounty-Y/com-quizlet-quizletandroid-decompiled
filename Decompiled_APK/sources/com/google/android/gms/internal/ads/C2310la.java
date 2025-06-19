package com.google.android.gms.internal.ads;

import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.la, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2310la implements InterfaceC2775w9 {
    public final C1920ca a;
    public final C2313ld b;
    public final /* synthetic */ com.google.android.gms.ads.internal.c c;

    public C2310la(com.google.android.gms.ads.internal.c cVar, C1920ca c1920ca, C2313ld c2313ld) {
        this.c = cVar;
        this.a = c1920ca;
        this.b = c2313ld;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2775w9
    public final void a(JSONObject jSONObject) {
        C1920ca c1920ca = this.a;
        C2313ld c2313ld = this.b;
        try {
            try {
                c2313ld.c(((InterfaceC2139ha) this.c.b).f(jSONObject));
            } catch (IllegalStateException unused) {
            } catch (JSONException e) {
                c2313ld.d(e);
            }
        } finally {
            c1920ca.v();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2775w9
    public final void zza(String str) {
        C1920ca c1920ca = this.a;
        C2313ld c2313ld = this.b;
        try {
            if (str == null) {
                c2313ld.d(new zzboc());
            } else {
                c2313ld.d(new zzboc(str));
            }
        } catch (IllegalStateException unused) {
        } catch (Throwable th) {
            c1920ca.v();
            throw th;
        }
        c1920ca.v();
    }
}
