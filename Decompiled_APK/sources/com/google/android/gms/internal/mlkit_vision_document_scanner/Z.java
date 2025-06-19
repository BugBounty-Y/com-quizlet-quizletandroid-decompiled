package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.SharedPreferences;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class Z {
    public static final /* synthetic */ int a = 0;

    public static int a(JSONObject jSONObject, int i, JSONObject jSONObject2, boolean z, com.onetrust.otpublishers.headless.Internal.Helper.c cVar, com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, JSONObject jSONObject3) throws JSONException {
        JSONArray jSONArray = jSONObject2.getJSONArray("SubGroups");
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < jSONArray.length(); i4++) {
            JSONObject jSONObject4 = jSONArray.getJSONObject(i4);
            if (jSONObject4.optString("Status", "").startsWith("always")) {
                i3++;
                i2++;
            } else {
                String strOptString = jSONObject4.optString("CustomGroupId", "-1");
                int i5 = (!z || cVar == null || dVar == null) ? jSONObject.has(strOptString) ? jSONObject.getInt(strOptString) : -1 : cVar.a(com.onetrust.otpublishers.headless.Internal.Helper.c.q(strOptString), "purposeLegitimateInterests", "active", dVar, false, jSONObject3);
                if (i5 == 0) {
                    return 0;
                }
                if (i5 < 0) {
                    i3++;
                }
            }
        }
        if (i2 > 0) {
            if (i2 != jSONArray.length()) {
                return 1;
            }
        } else if (i3 != jSONArray.length()) {
            return 1;
        }
        return i;
    }

    public static void b(int i, int i2, String str, JSONObject jSONObject) throws JSONException {
        if (jSONObject.has("purposeLegitimateInterests")) {
            JSONObject jSONObject2 = jSONObject.getJSONObject("purposeLegitimateInterests");
            if (i < 0 || i == i2) {
                return;
            }
            jSONObject2.put(com.onetrust.otpublishers.headless.Internal.Helper.c.q(str), i2);
            jSONObject.put("purposeLegitimateInterests", jSONObject2);
            OTLogger.c("OneTrust", 3, "setting LI status of " + str + " to " + i2 + "as per status configured for its subgroups");
        }
    }

    public static void c(String str, boolean z, JSONObject jSONObject, com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, Context context) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        JSONObject jSONObject2;
        try {
            JSONObject jSONObject3 = new JSONObject(dVar.b().getString("OTT_CONSENT_STATUS", "{}"));
            JSONArray jSONArray = new JSONObject(str).getJSONArray("Groups");
            boolean z2 = false;
            boolean z3 = jSONObject != null ? jSONObject.getBoolean("PAllowLI") : false;
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z2 = true;
            } else {
                fVar = null;
            }
            if (z2) {
                sharedPreferences = fVar;
            }
            String string = sharedPreferences.getString("OTT_CULTURE_DOMAIN_DATA", "");
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject2 = new JSONObject();
            } else {
                try {
                    jSONObject2 = new JSONObject(string);
                } catch (JSONException e) {
                    OTLogger.c("OneTrust", 6, "error while returning culture domain data, err: " + e.getMessage());
                }
            }
            if (jSONArray != null && jSONArray.length() > 0) {
                e(jSONArray, jSONObject3, context, jSONObject2);
                if (z && z3) {
                    d(jSONArray, new com.onetrust.otpublishers.headless.Internal.Helper.c(context), dVar, jSONObject2);
                }
            }
            dVar.b().edit().putString("OTT_CONSENT_STATUS", jSONObject3.toString()).apply();
        } catch (JSONException e2) {
            com.google.android.gms.measurement.internal.Z.o("error while setting default status of parent category,err: ", e2, "OneTrust");
        }
    }

    public static void d(JSONArray jSONArray, com.onetrust.otpublishers.headless.Internal.Helper.c cVar, com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, JSONObject jSONObject) throws JSONException {
        try {
            String string = dVar.b().getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
            JSONObject jSONObject2 = new JSONObject();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject2 = new JSONObject(string);
            }
            for (int i = 0; i < jSONArray.length(); i++) {
                JSONObject jSONObject3 = jSONArray.getJSONObject(i);
                if (jSONObject3.has("SubGroups")) {
                    String strOptString = jSONObject3.optString("CustomGroupId", "-1");
                    int iA = cVar.a(com.onetrust.otpublishers.headless.Internal.Helper.c.q(strOptString), "purposeLegitimateInterests", "active", dVar, false, jSONObject);
                    b(iA, a(new JSONObject(), iA, jSONObject3, true, cVar, dVar, jSONObject), strOptString, jSONObject2);
                }
            }
            dVar.b().edit().putString("OTT_IAB_CONSENTABLE_PURPOSES", jSONObject2.toString()).apply();
        } catch (JSONException e) {
            com.google.android.gms.measurement.internal.Z.o("error while setting default LI status of parent category,err: ", e, "OneTrust");
        }
    }

    public static void e(JSONArray jSONArray, JSONObject jSONObject, Context context, JSONObject jSONObject2) throws JSONException {
        JSONObject jSONObject3;
        JSONObject jSONObject4;
        int i = 0;
        while (i < jSONArray.length()) {
            try {
                JSONObject jSONObject5 = jSONArray.getJSONObject(i);
                if (jSONObject5.has("SubGroups") && jSONObject5.has("CustomGroupId") && !jSONObject5.getString("Status").contains("always")) {
                    String string = jSONObject5.getString("CustomGroupId");
                    int i2 = jSONObject.getInt(string);
                    jSONObject3 = jSONObject;
                    jSONObject4 = jSONObject2;
                    f(jSONObject3, string, a(jSONObject3, i2, jSONObject5, false, null, null, jSONObject4), i2, context);
                } else {
                    jSONObject3 = jSONObject;
                    jSONObject4 = jSONObject2;
                }
                i++;
                jSONObject = jSONObject3;
                jSONObject2 = jSONObject4;
            } catch (JSONException e) {
                com.google.android.gms.measurement.internal.Z.o("error while setting default consent status of parent category,err: ", e, "OneTrust");
                return;
            }
        }
    }

    public static void f(JSONObject jSONObject, String str, int i, int i2, Context context) throws JSONException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        if (i2 < 0 || i2 == i) {
            return;
        }
        jSONObject.put(str, i);
        OTLogger.c("OneTrust", 3, "setting consent status of " + str + " to " + i + "as per status configured for its subgroups");
        OTLogger.c("OTT_CONSENT_STATUS", 3, "Updating SDK status of the parent category.");
        com.onetrust.otpublishers.headless.Internal.Helper.g gVar = new com.onetrust.otpublishers.headless.Internal.Helper.g(context);
        boolean z = true;
        boolean z2 = i == 1;
        JSONArray jSONArrayF = gVar.f(str);
        boolean z3 = false;
        for (int i3 = 0; i3 < jSONArrayF.length(); i3++) {
            try {
                gVar.h(jSONArrayF.get(i3).toString(), z2);
                z3 = true;
            } catch (JSONException e) {
                com.google.android.gms.measurement.internal.Z.p("Error while Updating consent of SDK ", e, "SdkListHelper", 6);
            }
        }
        if (z3) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (com.google.android.gms.measurement.internal.Z.r(Boolean.FALSE, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            } else {
                z = false;
                fVar = null;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            gVar.g(sharedPreferences.getString("OT_INTERNAL_SDK_STATUS_MAP", ""));
        }
    }
}
