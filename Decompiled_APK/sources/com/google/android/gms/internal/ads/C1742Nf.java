package com.google.android.gms.internal.ads;

import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Nf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1742Nf implements CC {
    public final /* synthetic */ int a;
    public final C2702ug b;

    public /* synthetic */ C1742Nf(C2702ug c2702ug, int i) {
        this.a = i;
        this.b = c2702ug;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final /* bridge */ /* synthetic */ Object zzb() {
        switch (this.a) {
            case 0:
                try {
                    return new JSONObject(this.b.a().z);
                } catch (JSONException unused) {
                    return null;
                }
            default:
                return new C1842aj(this.b.a());
        }
    }
}
