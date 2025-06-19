package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class r {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e b;

    public r(@NonNull Context context) {
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        this.a = dVar;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.e(dVar);
    }

    public final void a(Context context, String str) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        OTLogger.c("consentLoggingDH", 4, "override data subject identifier : " + str);
        JSONObject jSONObject = new JSONObject();
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = this.b;
        String string = eVar.a.b().getString("OTT_DATA_SUBJECT_IDENTIFIER", "");
        if (string == null) {
            string = "";
        }
        if (string.equals(str)) {
            return;
        }
        eVar.k(str);
        c();
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(dVar.b().getString("OTT_CONSENT_LOG_DATA", ""))) {
            jSONObject = new JSONObject(dVar.b().getString("OTT_CONSENT_LOG_DATA", ""));
        }
        if (jSONObject.length() > 0) {
            boolean z = false;
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (Q.a(context)) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                fVar = null;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            if (sharedPreferences.getInt("OTT_USER_CONSENT_STATUS", -1) == 1) {
                OTLogger.c("consentLoggingDH", 4, "Consent logging with overridden data subject identifier");
                if (jSONObject.getJSONObject("consentPayload").getJSONArray("purposes").length() > 0) {
                    new com.onetrust.otpublishers.headless.Internal.Network.d(context).b(1, jSONObject.getString("consentApi"), jSONObject.getJSONObject("consentPayload").toString());
                }
            }
        }
    }

    public final void b(androidx.compose.foundation.text.input.internal.u uVar) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        jSONObject.put("identifier", (String) ((com.quizlet.data.repository.login.a) uVar.c).c);
        jSONObject.put("purposes", (JSONArray) ((com.quizlet.data.repository.login.a) uVar.c).b);
        jSONObject.put("requestInformation", (String) ((com.quizlet.data.repository.login.a) uVar.c).a);
        jSONObject2.put("consentApi", (String) uVar.b);
        jSONObject2.put("consentPayload", jSONObject);
        OTLogger.c("consent data", 3, "data" + jSONObject2);
        String string = jSONObject2.toString();
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        dVar.b().edit().putString("OTT_CONSENT_LOG_DATA", string).apply();
        L.i(jSONObject2, dVar.b().edit(), "OT_CL_DEFAULT_PAYLOAD");
        if (dVar.b().getString("OT_CL_DEFAULT_PAYLOAD", "").isEmpty()) {
            return;
        }
        String string2 = dVar.b().getString("OT_CL_DEFAULT_PAYLOAD", "");
        String string3 = dVar.b().getString("OT_CL_DEFAULT_TRANSACTION_VALUES", "");
        JSONObject jSONObject3 = new JSONObject(string2);
        jSONObject3.getJSONObject("consentPayload").put("purposes", new JSONArray(string3));
        OTLogger.c("consentLoggingDH", 3, "default payload " + jSONObject3);
        L.i(jSONObject3, dVar.b().edit(), "OT_CL_DEFAULT_PAYLOAD");
    }

    public final void c() {
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        try {
            if (com.onetrust.otpublishers.headless.Internal.a.j(dVar.b().getString("OTT_CONSENT_LOG_DATA", ""))) {
                return;
            }
            OTLogger.c("consentLoggingDH", 4, "setting DSID to Consent payload");
            JSONObject jSONObject = new JSONObject(dVar.b().getString("OTT_CONSENT_LOG_DATA", ""));
            String string = this.b.a.b().getString("OTT_DATA_SUBJECT_IDENTIFIER", "");
            if (string == null) {
                string = "";
            }
            jSONObject.getJSONObject("consentPayload").put("identifier", string);
            dVar.b().edit().putString("OTT_CONSENT_LOG_DATA", jSONObject.toString()).apply();
            if (dVar.b().getString("OT_CL_DEFAULT_PAYLOAD", "").isEmpty()) {
                return;
            }
            JSONObject jSONObject2 = new JSONObject(dVar.b().getString("OT_CL_DEFAULT_PAYLOAD", ""));
            jSONObject2.getJSONObject("consentPayload").put("identifier", string);
            dVar.b().edit().putString("OT_CL_DEFAULT_PAYLOAD", jSONObject2.toString()).apply();
        } catch (Exception e) {
            Z.n("error while setting DSID to consent payload", e, "consentLoggingDH", 6);
        }
    }
}
