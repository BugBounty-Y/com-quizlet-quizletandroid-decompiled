package com.onetrust.otpublishers.headless.gpp.templates;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.compose.ui.node.B;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import java.util.HashMap;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class f {
    public final Context a;

    public f(@NonNull Context context) {
        this.a = context;
    }

    public static StringBuilder a(JSONObject jSONObject, JSONObject jSONObject2, com.onetrust.otpublishers.headless.gpp.d dVar) {
        int iA;
        int iA2;
        int iA3;
        int iA4;
        int iA5;
        int iA6;
        int iA7;
        int iA8;
        if (jSONObject.optBoolean("sensitiveDataProcessApplicable")) {
            iA = dVar.a(jSONObject2.optString("race"));
            iA3 = dVar.a(jSONObject2.optString("religion"));
            iA4 = dVar.a(jSONObject2.optString("health"));
            iA5 = dVar.a(jSONObject2.optString("sexualOrientation"));
            iA6 = dVar.a(jSONObject2.optString("immigration"));
            iA7 = dVar.a(jSONObject2.optString("genetic"));
            iA8 = dVar.a(jSONObject2.optString("biometric"));
            iA2 = dVar.a(jSONObject2.optString("geolocation"));
        } else {
            iA = 0;
            iA2 = 0;
            iA3 = 0;
            iA4 = 0;
            iA5 = 0;
            iA6 = 0;
            iA7 = 0;
            iA8 = 0;
        }
        HashMap map = new HashMap();
        B.r(iA, map, "sdp1", iA3, "sdp2");
        B.r(iA4, map, "sdp3", iA5, "sdp4");
        B.r(iA6, map, "sdp5", iA7, "sdp6");
        B.r(iA8, map, "sdp7", iA2, "sdp8");
        return com.onetrust.otpublishers.headless.gpp.d.b(map, new String[]{"sdp1", "sdp2", "sdp3", "sdp4", "sdp5", "sdp6", "sdp7", "sdp8"});
    }

    public final void b() {
        Context context = this.a;
        try {
            if (new com.onetrust.otpublishers.headless.gpp.d(context).d("CDPA")) {
                return;
            }
            String strC = c();
            OTLogger.c("OneTrust", 4, "Gpp - CDPA (Virginia) String : " + strC);
            if (com.onetrust.otpublishers.headless.Internal.a.j(strC)) {
                return;
            }
            new com.onetrust.otpublishers.headless.Internal.Preferences.a(context).c(OTGppKeys.IAB_GPP_USVA_STRING, strC);
        } catch (Exception e) {
            OTLogger.c("OneTrust", 6, "computeVirginiaString failed:" + e);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00ec  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String c() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 376
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.gpp.templates.f.c():java.lang.String");
    }
}
