package com.facebook;

import androidx.compose.foundation.lazy.layout.n0;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements q {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.facebook.q
    public final void a(w response) {
        JSONObject jSONObject;
        JSONObject jSONObject2;
        switch (this.a) {
            case 0:
                n0 refreshResult = (n0) this.b;
                Intrinsics.checkNotNullParameter(refreshResult, "$refreshResult");
                Intrinsics.checkNotNullParameter(response, "response");
                JSONObject jSONObject3 = response.d;
                if (jSONObject3 != null) {
                    refreshResult.c = jSONObject3.optString("access_token");
                    refreshResult.a = jSONObject3.optInt("expires_at");
                    refreshResult.b = jSONObject3.optInt("expires_in");
                    refreshResult.d = Long.valueOf(jSONObject3.optLong("data_access_expiration_time"));
                    refreshResult.e = jSONObject3.optString("graph_domain", null);
                    break;
                }
                break;
            case 1:
                com.facebook.internal.instrument.c instrumentData = (com.facebook.internal.instrument.c) this.b;
                Intrinsics.checkNotNullParameter(instrumentData, "$instrumentData");
                Intrinsics.checkNotNullParameter(response, "response");
                try {
                    if (response.c == null && (jSONObject = response.d) != null && jSONObject.getBoolean("success")) {
                        G2.c(instrumentData.a);
                        break;
                    }
                } catch (JSONException unused) {
                    return;
                }
                break;
            default:
                ArrayList validReports = (ArrayList) this.b;
                Intrinsics.checkNotNullParameter(validReports, "$validReports");
                Intrinsics.checkNotNullParameter(response, "response");
                try {
                    if (response.c == null && (jSONObject2 = response.d) != null && jSONObject2.getBoolean("success")) {
                        Iterator it2 = validReports.iterator();
                        while (it2.hasNext()) {
                            G2.c(((com.facebook.internal.instrument.errorreport.a) it2.next()).a);
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
