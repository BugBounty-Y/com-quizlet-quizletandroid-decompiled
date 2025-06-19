package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import androidx.annotation.NonNull;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class i {
    public final Context a;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d b;
    public final k c;

    public i(@NonNull Context context) {
        this.a = context;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        this.c = new k(context);
    }

    public static void c(JSONObject jSONObject, JSONObject jSONObject2, JSONArray jSONArray, JSONArray jSONArray2, JSONObject jSONObject3, JSONObject jSONObject4) throws JSONException {
        if ((!(jSONObject.optString("userConsentStatus").equals("ACTIVE") && jSONObject.optString("transactionType").equals("OPT_OUT")) && jSONObject.optString("userConsentStatus").equals("ACTIVE") && jSONObject.optString("transactionType").equals("ACTIVE")) ? !jSONObject4.optString("userConsentStatus").equals(jSONObject4.optString("transactionType")) : false) {
            jSONObject2.put("TransactionType", "CHANGE_PREFERENCES");
            jSONObject3.put("OptionId", jSONObject4.optString("id"));
            jSONObject3.put("TransactionType", jSONObject4.optString("userConsentStatus").equals("OPT_IN") ? "OPT_IN" : "OPT_OUT");
            jSONArray.put(jSONObject3);
            return;
        }
        if (!jSONObject.optString("userConsentStatus").equals("ACTIVE") || jSONObject2.getString("TransactionType").equals("CHANGE_PREFERENCES")) {
            return;
        }
        jSONObject2.put("TransactionType", "CONFIRMED");
        if (jSONObject4.getString("userConsentStatus").equals("OPT_IN")) {
            jSONArray2.put(jSONObject4.optString("id"));
        }
    }

    public static void d(JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3, String str, JSONArray jSONArray) throws JSONException {
        JSONObject jSONObject4 = jSONObject;
        int i = 0;
        while (i < jSONObject4.length()) {
            JSONObject jSONObject5 = new JSONObject();
            JSONObject jSONObjectOptJSONObject = jSONObject4.optJSONObject(jSONObject4.getJSONObject(jSONObject4.names().get(i).toString()).optString("purposeTopicId"));
            String strOptString = jSONObjectOptJSONObject.optString("id");
            if (jSONObjectOptJSONObject.optString("purposeId").equals(str)) {
                String str2 = "OPT_IN";
                if ((jSONObject3.optString("userConsentStatus").equals("ACTIVE") && jSONObject3.optString("transactionType").equals("OPT_OUT") && jSONObjectOptJSONObject.optString("transactionType").equals("OPT_IN")) || (jSONObject3.optString("userConsentStatus").equals("ACTIVE") && jSONObject3.optString("transactionType").equals("OPT_OUT") && jSONObjectOptJSONObject.optString("userConsentStatus").equals("OPT_IN"))) {
                    jSONObject5.put("TopicId", strOptString);
                    jSONObject2.put("TransactionType", "CONFIRMED");
                } else if (jSONObject3.optString("userConsentStatus").equals("ACTIVE") && jSONObject3.optString("transactionType").equals("ACTIVE") && jSONObjectOptJSONObject.optString("userConsentStatus").equals("OPT_IN")) {
                    if (!jSONObjectOptJSONObject.optString("userConsentStatus").equals(jSONObjectOptJSONObject.optString("transactionType"))) {
                        jSONObject5.put("TopicId", strOptString);
                        jSONObject5.put("TransactionType", str2);
                        jSONObject2.put("TransactionType", "CHANGE_PREFERENCES");
                    }
                } else if (jSONObject3.optString("userConsentStatus").equals("ACTIVE") && jSONObject3.optString("transactionType").equals("ACTIVE") && jSONObjectOptJSONObject.optString("userConsentStatus").equals("OPT_OUT") && !jSONObjectOptJSONObject.optString("userConsentStatus").equals(jSONObjectOptJSONObject.optString("transactionType"))) {
                    str2 = "OPT_OUT";
                    jSONObject5.put("TopicId", strOptString);
                    jSONObject5.put("TransactionType", str2);
                    jSONObject2.put("TransactionType", "CHANGE_PREFERENCES");
                }
                if (!jSONObject5.toString().equals("{}")) {
                    jSONArray.put(jSONObject5);
                }
            }
            i++;
            jSONObject4 = jSONObject;
        }
        jSONObject2.put("Preferences", jSONArray);
    }

    public final JSONArray a() {
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
        String string = dVar.b().getString("OT_UC_PURPOSES_PURPOSE_SERVER_DATA", "");
        String string2 = dVar.b().getString("OT_UC_PURPOSES_CUSTOM_PREF_OPTIONS_SERVER_DATA", "");
        String string3 = dVar.b().getString("OT_UC_PURPOSES_TOPIC_SERVER_DATA", "");
        JSONArray jSONArray = new JSONArray();
        try {
            b(jSONArray, new JSONObject(string), new JSONObject(string2), new JSONObject(string3));
        } catch (JSONException e) {
            Z.p("Error in fetching saved ucp data :", e, "UCPConsentLoggingData", 6);
        }
        OTLogger.c("UCPConsentLoggingData", 3, "UCP consent payload :" + jSONArray);
        return jSONArray;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0132 A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r12v0, types: [java.lang.Object, org.json.JSONObject] */
    /* JADX WARN: Type inference failed for: r13v1, types: [org.json.JSONArray] */
    /* JADX WARN: Type inference failed for: r13v2 */
    /* JADX WARN: Type inference failed for: r13v3 */
    /* JADX WARN: Type inference failed for: r21v0, types: [org.json.JSONArray] */
    /* JADX WARN: Type inference failed for: r9v11 */
    /* JADX WARN: Type inference failed for: r9v12 */
    /* JADX WARN: Type inference failed for: r9v14 */
    /* JADX WARN: Type inference failed for: r9v15, types: [java.lang.Object, org.json.JSONArray] */
    /* JADX WARN: Type inference failed for: r9v23 */
    /* JADX WARN: Type inference failed for: r9v8 */
    /* JADX WARN: Type inference failed for: r9v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(org.json.JSONArray r21, org.json.JSONObject r22, org.json.JSONObject r23, org.json.JSONObject r24) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 326
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.i.b(org.json.JSONArray, org.json.JSONObject, org.json.JSONObject, org.json.JSONObject):void");
    }

    public final boolean e(String str, JSONObject jSONObject, JSONObject jSONObject2) {
        boolean z;
        int i = jSONObject.getInt("status");
        k kVar = this.c;
        int iU = kVar.u(str);
        if (i != iU) {
            jSONObject.put("status", iU);
            z = true;
        } else {
            z = false;
        }
        JSONObject jSONObject3 = jSONObject.getJSONObject("topics");
        if (!retrofit2.adapter.rxjava3.d.o(jSONObject3)) {
            JSONArray jSONArrayNames = jSONObject3.names();
            for (int i2 = 0; i2 < jSONObject3.length(); i2++) {
                String string = jSONArrayNames.getString(i2);
                int i3 = jSONObject3.getInt(string);
                int iA = kVar.a(string, str);
                if (i3 != iA) {
                    jSONObject3.put(string, iA);
                    z = true;
                }
            }
        }
        JSONObject jSONObject4 = jSONObject.getJSONObject("custom_preferences");
        if (!retrofit2.adapter.rxjava3.d.o(jSONObject4)) {
            for (int i4 = 0; i4 < jSONObject4.length(); i4++) {
                String string2 = jSONObject4.names().getString(i4);
                JSONObject jSONObject5 = jSONObject4.getJSONObject(string2);
                for (int i5 = 0; i5 < jSONObject5.length(); i5++) {
                    String string3 = jSONObject5.names().getString(i5);
                    int i6 = jSONObject5.getInt(string3);
                    int iB = kVar.b(string3, str, string2);
                    if (i6 != iB) {
                        jSONObject5.put(string3, iB);
                        z = true;
                    }
                }
            }
        }
        if (z) {
            jSONObject2.put(str, jSONObject);
        }
        return z;
    }
}
