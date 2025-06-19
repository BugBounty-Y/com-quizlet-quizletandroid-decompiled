package com.google.android.gms.internal.ads;

import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Xm implements InterfaceC2837xm {
    public final C2663tk a;

    public Xm(C2663tk c2663tk) {
        this.a = c2663tk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2837xm
    public final C2880ym a(String str, JSONObject jSONObject) {
        return new C2880ym(this.a.b(str, jSONObject), new Rm(), str);
    }
}
