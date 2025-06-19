package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class q {
    public final Context a;
    public final SharedPreferences b;

    public q(@NonNull Context context) {
        this.a = context;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context).b();
    }

    public final void a(JSONObject jSONObject, boolean z) throws JSONException {
        SharedPreferences sharedPreferences = this.b;
        String string = sharedPreferences.getString("OTT_CONSENT_LOG_DATA", "");
        String string2 = sharedPreferences.getString("OT_CL_DEFAULT_PAYLOAD", "");
        String str = "consentLogging not initialized.";
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            Context context = this.a;
            if (!z || !new OTPublishersHeadlessSDK(context).shouldShowBanner()) {
                try {
                    JSONObject jSONObject2 = new JSONObject(string);
                    if (b(jSONObject2, jSONObject, z)) {
                        L.i(jSONObject2, new r(context).a.b().edit(), "OTT_CONSENT_LOG_DATA");
                        String string3 = jSONObject2.getString("consentApi");
                        String string4 = jSONObject2.getJSONObject("consentPayload").toString();
                        OTLogger.c("ConsentLogging", 4, "payloadObj" + string4);
                        OTLogger.c("ConsentLogging", 4, "consent obj" + jSONObject2);
                        new com.onetrust.otpublishers.headless.Internal.Network.d(context).b(1, string3, string4);
                        return;
                    }
                    return;
                } catch (JSONException e) {
                    Z.p("error in reading old consent data. error - ", e, "ConsentLogging", 6);
                    return;
                }
            }
            try {
                if (com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    OTLogger.c("ConsentLogging", 5, "consentLogging not initialized.");
                    return;
                }
                JSONObject jSONObject3 = new JSONObject(string2);
                OTLogger.c("ConsentLogging", 4, "payloadObj default" + jSONObject3.getJSONObject("consentPayload"));
                OTLogger.c("ConsentLogging", 4, "consent obj default" + jSONObject3);
                new com.onetrust.otpublishers.headless.Internal.Network.d(context).b(1, jSONObject3.getString("consentApi"), jSONObject3.getJSONObject("consentPayload").toString());
                return;
            } catch (JSONException e2) {
                str = "Error while logging consent for default values." + e2.getMessage();
            }
        }
        OTLogger.c("ConsentLogging", 5, str);
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00e5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b(org.json.JSONObject r20, org.json.JSONObject r21, boolean r22) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.q.b(org.json.JSONObject, org.json.JSONObject, boolean):boolean");
    }
}
