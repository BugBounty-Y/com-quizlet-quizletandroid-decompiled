package com.facebook.internal.instrument.anrreport;

import com.facebook.q;
import com.facebook.w;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements q {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    public /* synthetic */ b(List list, int i) {
        this.a = i;
        this.b = list;
    }

    @Override // com.facebook.q
    public final void a(w response) {
        JSONObject jSONObject;
        JSONObject jSONObject2;
        switch (this.a) {
            case 0:
                List validReports = this.b;
                if (!com.facebook.internal.instrument.crashshield.a.b(c.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(validReports, "$validReports");
                        Intrinsics.checkNotNullParameter(response, "response");
                        try {
                            if (response.c == null && (jSONObject = response.d) != null && jSONObject.getBoolean("success")) {
                                Iterator it2 = validReports.iterator();
                                while (it2.hasNext()) {
                                    G2.c(((com.facebook.internal.instrument.c) it2.next()).a);
                                }
                                break;
                            }
                        } catch (JSONException unused) {
                            return;
                        }
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(c.class, th);
                        return;
                    }
                }
                break;
            default:
                List validReports2 = this.b;
                Intrinsics.checkNotNullParameter(validReports2, "$validReports");
                Intrinsics.checkNotNullParameter(response, "response");
                try {
                    if (response.c == null && (jSONObject2 = response.d) != null && jSONObject2.getBoolean("success")) {
                        Iterator it3 = validReports2.iterator();
                        while (it3.hasNext()) {
                            G2.c(((com.facebook.internal.instrument.c) it3.next()).a);
                        }
                        break;
                    }
                } catch (JSONException unused2) {
                    return;
                }
                break;
        }
    }
}
