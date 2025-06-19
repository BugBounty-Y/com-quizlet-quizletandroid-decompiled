package com.google.android.gms.internal.ads;

import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.v9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2732v9 implements InterfaceC2775w9 {
    public final /* synthetic */ int a;
    public final C2313ld b;

    public /* synthetic */ C2732v9(C2313ld c2313ld, int i) {
        this.a = i;
        this.b = c2313ld;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2775w9
    public final void a(JSONObject jSONObject) {
        switch (this.a) {
            case 0:
                this.b.c(jSONObject);
                break;
            default:
                C2313ld c2313ld = this.b;
                try {
                    c2313ld.c(jSONObject);
                    break;
                } catch (IllegalStateException unused) {
                    return;
                } catch (JSONException e) {
                    c2313ld.d(e);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2775w9
    public final void zza(String str) {
        switch (this.a) {
            case 0:
                this.b.d(new zzboc(str));
                break;
            default:
                C2313ld c2313ld = this.b;
                try {
                    if (str == null) {
                        c2313ld.d(new zzboc());
                    } else {
                        c2313ld.d(new zzboc(str));
                    }
                    break;
                } catch (IllegalStateException unused) {
                    return;
                }
        }
    }
}
