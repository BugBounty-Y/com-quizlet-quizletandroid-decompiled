package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.co, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1934co implements Uo {
    public final /* synthetic */ int a;
    public final String b;

    public /* synthetic */ C1934co(String str, int i) {
        this.a = i;
        this.b = str;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    private final /* synthetic */ void e(Object obj) {
    }

    private final /* synthetic */ void f(Object obj) {
    }

    private final /* synthetic */ void g(Object obj) {
    }

    private final /* synthetic */ void h(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        int i = this.a;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) throws JSONException {
        switch (this.a) {
            case 0:
                Og og = (Og) obj;
                String str = this.b;
                if (str != null) {
                    og.a.putString("arek", str);
                    break;
                }
                break;
            case 1:
                ((Og) obj).a.putString("ms", this.b);
                break;
            case 2:
                AbstractC2096gb.t("key_schema", this.b, ((Og) obj).a);
                break;
            case 3:
                AbstractC2096gb.t("omid_v", this.b, ((Og) obj).a);
                break;
            case 4:
                try {
                    ((JSONObject) obj).put("ms", this.b);
                    break;
                } catch (JSONException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                    return;
                }
            default:
                JSONObject jSONObject = (JSONObject) obj;
                try {
                    String str2 = this.b;
                    if (!TextUtils.isEmpty(str2)) {
                        com.google.android.gms.internal.mlkit_vision_common.V2.f("pii", jSONObject).put("adsid", str2);
                        break;
                    }
                } catch (JSONException e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Failed putting trustless token.", e);
                }
                break;
        }
    }
}
