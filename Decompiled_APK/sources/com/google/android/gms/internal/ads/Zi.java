package com.google.android.gms.internal.ads;

import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Zi extends C1842aj {
    public final JSONObject b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final String g;
    public final JSONObject h;

    public Zi(Vp vp, JSONObject jSONObject) {
        super(vp);
        String[] strArr = {"tracking_urls_and_actions", "active_view"};
        JSONObject jSONObjectK = com.google.android.gms.internal.mlkit_vision_common.V2.k(jSONObject, strArr);
        this.b = jSONObjectK == null ? null : jSONObjectK.optJSONObject(strArr[1]);
        String[] strArr2 = {"allow_pub_owned_ad_view"};
        JSONObject jSONObjectK2 = com.google.android.gms.internal.mlkit_vision_common.V2.k(jSONObject, strArr2);
        this.c = jSONObjectK2 == null ? false : jSONObjectK2.optBoolean(strArr2[0], false);
        String[] strArr3 = {"attribution", "allow_pub_rendering"};
        JSONObject jSONObjectK3 = com.google.android.gms.internal.mlkit_vision_common.V2.k(jSONObject, strArr3);
        this.d = jSONObjectK3 == null ? false : jSONObjectK3.optBoolean(strArr3[1], false);
        String[] strArr4 = {"enable_omid"};
        JSONObject jSONObjectK4 = com.google.android.gms.internal.mlkit_vision_common.V2.k(jSONObject, strArr4);
        this.e = jSONObjectK4 == null ? false : jSONObjectK4.optBoolean(strArr4[0], false);
        String[] strArr5 = {"watermark_overlay_png_base64"};
        JSONObject jSONObjectK5 = com.google.android.gms.internal.mlkit_vision_common.V2.k(jSONObject, strArr5);
        this.g = jSONObjectK5 != null ? jSONObjectK5.optString(strArr5[0], "") : "";
        this.f = jSONObject.optJSONObject("overlay") != null;
        this.h = jSONObject.optJSONObject("omid_settings");
    }

    @Override // com.google.android.gms.internal.ads.C1842aj
    public final C2881yn a() {
        JSONObject jSONObject = this.h;
        return jSONObject != null ? new C2881yn(jSONObject, 28) : this.a.V;
    }

    @Override // com.google.android.gms.internal.ads.C1842aj
    public final String b() {
        return this.g;
    }

    @Override // com.google.android.gms.internal.ads.C1842aj
    public final boolean c() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.C1842aj
    public final boolean d() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.C1842aj
    public final boolean e() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.C1842aj
    public final boolean f() {
        return this.f;
    }
}
