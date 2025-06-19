package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.C1614q;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.io, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2196io implements Uo {
    public final /* synthetic */ int a;
    public final Bundle b;

    public /* synthetic */ C2196io(Bundle bundle, int i) {
        this.a = i;
        this.b = bundle;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    private final /* synthetic */ void e(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        switch (this.a) {
            case 2:
                Og og = (Og) obj;
                Bundle bundle = this.b;
                if (bundle != null) {
                    og.b.putAll(bundle);
                    break;
                }
                break;
            case 3:
                Og og2 = (Og) obj;
                Bundle bundle2 = this.b;
                if (!bundle2.isEmpty()) {
                    og2.b.putBundle("shared_pref", bundle2);
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) throws JSONException {
        switch (this.a) {
            case 0:
                Og og = (Og) obj;
                Bundle bundle = this.b;
                if (!bundle.isEmpty()) {
                    og.a.putBundle("installed_adapter_data", bundle);
                    break;
                }
                break;
            case 1:
                Bundle bundle2 = ((Og) obj).a;
                Bundle bundleD = AbstractC2096gb.d(bundle2, "device");
                bundleD.putBundle("android_mem_info", this.b);
                bundle2.putBundle("device", bundleD);
                break;
            case 2:
                Og og2 = (Og) obj;
                Bundle bundle3 = this.b;
                if (bundle3 != null) {
                    og2.a.putAll(bundle3);
                    break;
                }
                break;
            case 3:
                Og og3 = (Og) obj;
                Bundle bundle4 = this.b;
                if (!bundle4.isEmpty()) {
                    og3.a.putBundle("shared_pref", bundle4);
                    break;
                }
                break;
            default:
                JSONObject jSONObject = (JSONObject) obj;
                Bundle bundle5 = this.b;
                if (bundle5 != null) {
                    try {
                        com.google.android.gms.internal.mlkit_vision_common.V2.f("play_store", com.google.android.gms.internal.mlkit_vision_common.V2.f("device", jSONObject)).put("parental_controls", C1614q.f.a.h(bundle5));
                        break;
                    } catch (JSONException unused) {
                        com.google.android.gms.ads.internal.util.A.l("Failed putting parental controls bundle.");
                    }
                }
                break;
        }
    }
}
