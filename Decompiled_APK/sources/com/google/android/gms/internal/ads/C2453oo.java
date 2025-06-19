package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.oo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2453oo implements Uo {
    public final /* synthetic */ int a;
    public final String b;
    public final int c;

    public /* synthetic */ C2453oo(String str, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = i;
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
            case 1:
                ((Og) obj).b.putString("request_id", this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) throws JSONException {
        int i;
        int i2;
        switch (this.a) {
            case 0:
                Bundle bundle = ((Og) obj).a;
                String str = this.b;
                if (!TextUtils.isEmpty(str) && (i = this.c) != -1) {
                    Bundle bundleD = AbstractC2096gb.d(bundle, "pii");
                    bundle.putBundle("pii", bundleD);
                    bundleD.putString("pvid", str);
                    bundleD.putInt("pvid_s", i);
                    break;
                }
                break;
            case 1:
                Bundle bundle2 = ((Og) obj).a;
                bundle2.putString("request_id", this.b);
                if (this.c == 2) {
                    bundle2.putInt("sod", 1);
                    break;
                }
                break;
            case 2:
                Og og = (Og) obj;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ta)).booleanValue()) {
                    String str2 = this.b;
                    boolean zIsEmpty = TextUtils.isEmpty(str2);
                    Bundle bundle3 = og.a;
                    if (!zIsEmpty) {
                        bundle3.putString("topics", str2);
                    }
                    int i3 = this.c;
                    if (i3 != -1) {
                        bundle3.putInt("atps", i3);
                        break;
                    }
                }
                break;
            default:
                JSONObject jSONObject = (JSONObject) obj;
                String str3 = this.b;
                if (!TextUtils.isEmpty(str3) && (i2 = this.c) != -1) {
                    try {
                        JSONObject jSONObjectF = com.google.android.gms.internal.mlkit_vision_common.V2.f("pii", jSONObject);
                        jSONObjectF.put("pvid", str3);
                        jSONObjectF.put("pvid_s", i2);
                        break;
                    } catch (JSONException unused) {
                        com.google.android.gms.ads.internal.util.A.m();
                    }
                }
                break;
        }
    }
}
