package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.go, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2109go implements Uo {
    public final /* synthetic */ int a;
    public final ArrayList b;

    public /* synthetic */ C2109go(int i, ArrayList arrayList) {
        this.a = i;
        this.b = arrayList;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        switch (this.a) {
            case 0:
                ((Og) obj).b.putStringArrayList("ad_types", this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) throws JSONException {
        switch (this.a) {
            case 0:
                ((Og) obj).a.putStringArrayList("ad_types", this.b);
                break;
            case 1:
                AbstractC2096gb.y(((Og) obj).a, "android_permissions", this.b);
                break;
            default:
                try {
                    ((JSONObject) obj).put("eid", TextUtils.join(",", this.b));
                    break;
                } catch (JSONException unused) {
                    com.google.android.gms.ads.internal.util.A.l("Failed putting experiment ids.");
                }
        }
    }
}
