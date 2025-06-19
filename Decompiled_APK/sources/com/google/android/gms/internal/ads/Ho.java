package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.C1614q;
import java.util.HashMap;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Ho implements Uo {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ Ho(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    private final /* synthetic */ void e(Object obj) {
    }

    private final /* synthetic */ void f(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        int i = this.a;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) throws JSONException {
        boolean z;
        boolean z2;
        switch (this.a) {
            case 0:
                Og og = (Og) obj;
                Up up = (Up) this.b;
                if (up != null) {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ub)).booleanValue()) {
                        return;
                    }
                    Bundle bundle = og.a;
                    synchronized (up.c) {
                        up.b();
                        z = up.e == 2;
                    }
                    bundle.putBoolean("render_in_browser", z);
                    synchronized (up.c) {
                        up.b();
                        z2 = up.e == 3;
                    }
                    bundle.putBoolean("disable_ml", z2);
                    return;
                }
                return;
            case 1:
                try {
                    ((JSONObject) obj).put("cache_state", (JSONObject) this.b);
                    return;
                } catch (JSONException unused) {
                    com.google.android.gms.ads.internal.util.A.l("Unable to get cache_state");
                    return;
                }
            case 2:
                try {
                    ((JSONObject) obj).put("gms_sdk_env", ((C2110gp) this.b).a);
                    return;
                } catch (JSONException unused2) {
                    com.google.android.gms.ads.internal.util.A.l("Failed putting version constants.");
                    return;
                }
            default:
                try {
                    ((JSONObject) obj).put("video_decoders", C1614q.f.a.i((HashMap) this.b));
                    return;
                } catch (JSONException e) {
                    com.google.android.gms.ads.internal.util.A.l("Could not encode video decoder properties: ".concat(String.valueOf(e.getMessage())));
                    return;
                }
        }
    }
}
