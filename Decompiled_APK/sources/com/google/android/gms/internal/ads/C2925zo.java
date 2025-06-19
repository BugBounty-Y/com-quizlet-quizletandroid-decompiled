package com.google.android.gms.internal.ads;

import android.os.Bundle;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.zo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2925zo implements Uo {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ C2925zo(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        switch (this.a) {
            case 0:
                Og og = (Og) obj;
                JSONObject jSONObject = (JSONObject) this.c;
                if (jSONObject != null) {
                    og.b.putString("fwd_common_cld", jSONObject.toString());
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) throws JSONException {
        switch (this.a) {
            case 0:
                Bundle bundle = ((Og) obj).a;
                JSONObject jSONObject = (JSONObject) this.b;
                if (jSONObject != null) {
                    bundle.putString("fwd_cld", jSONObject.toString());
                }
                JSONObject jSONObject2 = (JSONObject) this.c;
                if (jSONObject2 != null) {
                    bundle.putString("fwd_common_cld", jSONObject2.toString());
                    break;
                }
                break;
            case 1:
                Bundle bundle2 = ((Og) obj).a;
                bundle2.putString("rtb", (String) this.b);
                Bundle bundle3 = (Bundle) this.c;
                if (!bundle3.isEmpty()) {
                    bundle2.putBundle("adapter_initialization_status", bundle3);
                    break;
                }
                break;
            default:
                try {
                    JSONObject jSONObjectF = com.google.android.gms.internal.mlkit_vision_common.V2.f("pii", (JSONObject) obj);
                    jSONObjectF.put("doritos", (String) this.b);
                    jSONObjectF.put("doritos_v2", (String) this.c);
                    break;
                } catch (JSONException unused) {
                    com.google.android.gms.ads.internal.util.A.l("Failed putting doritos string.");
                }
        }
    }
}
