package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;
import java.util.TimeZone;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class n {
    public final Context a;

    public n(@NonNull Context context) {
        this.a = context;
    }

    public final String a(JSONArray jSONArray, String str) throws JSONException {
        String str2;
        String str3 = "SubGroups";
        JSONObject jSONObject = new JSONObject(str);
        OTLogger.c("WebviewConsentHelper", 3, "OTSDK consented group and status = " + str);
        JSONObject jSONObject2 = new JSONObject();
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            try {
                Object obj = jSONObject.get(next);
                int i = 0;
                while (i < jSONArray.length()) {
                    try {
                        JSONObject jSONObject3 = jSONArray.getJSONObject(i);
                        if (jSONObject3.has(str3)) {
                            JSONArray jSONArray2 = jSONObject3.getJSONArray(str3);
                            str2 = str3;
                            try {
                                if (next.equals(jSONObject3.optString("CustomGroupId", "")) && "COOKIE".equals(jSONObject3.getString("Type")) && !jSONObject3.getBoolean("IsIabPurpose")) {
                                    jSONObject2.put(next, obj);
                                }
                                int i2 = 0;
                                while (i2 < jSONArray2.length()) {
                                    JSONObject jSONObject4 = jSONArray2.getJSONObject(i2);
                                    int i3 = i2;
                                    if (next.equals(jSONObject4.optString("CustomGroupId", "")) && "COOKIE".equals(jSONObject4.getString("Type")) && !jSONObject4.getBoolean("IsIabPurpose")) {
                                        jSONObject2.put(next, obj);
                                    }
                                    i2 = i3 + 1;
                                }
                            } catch (JSONException e) {
                                e = e;
                                Z.p("Error on parsing. Error msg = ", e, "WebviewConsentHelper", 6);
                                str3 = str2;
                            }
                        } else {
                            str2 = str3;
                            if (next.equals(jSONObject3.optString("CustomGroupId", "")) && "COOKIE".equals(jSONObject3.getString("Type")) && !jSONObject3.getBoolean("IsIabPurpose")) {
                                jSONObject2.put(next, obj);
                            }
                        }
                        i++;
                        str3 = str2;
                    } catch (JSONException e2) {
                        e = e2;
                        str2 = str3;
                        Z.p("Error on parsing. Error msg = ", e, "WebviewConsentHelper", 6);
                        str3 = str2;
                    }
                }
                str2 = str3;
            } catch (JSONException e3) {
                e = e3;
            }
            try {
                c(jSONObject2);
            } catch (JSONException e4) {
                e = e4;
                Z.p("Error on parsing. Error msg = ", e, "WebviewConsentHelper", 6);
                str3 = str2;
            }
            str3 = str2;
        }
        return jSONObject2.toString();
    }

    public final String b(boolean z) throws JSONException {
        boolean z2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z3;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar3;
        JSONObject jSONObject = new JSONObject();
        Context context = this.a;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        try {
            JSONObject preferenceCenterData = new OTPublishersHeadlessSDK(context).getPreferenceCenterData();
            if (preferenceCenterData == null) {
                OTLogger.c("WebviewConsentHelper", 5, "Consent for WebView: No app data found, returning empty JSON.");
            } else {
                JSONArray jSONArray = preferenceCenterData.getJSONArray("Groups");
                boolean z4 = false;
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0);
                Boolean bool = Boolean.FALSE;
                String str = "";
                if (AbstractC3605e0.a(sharedPreferences2.getString("OT_ENABLE_MULTI_PROFILE", bool.toString()))) {
                    fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z2 = true;
                } else {
                    z2 = false;
                    fVar = null;
                }
                if (z2) {
                    sharedPreferences = fVar;
                }
                jSONObject.put("groups", a(jSONArray, sharedPreferences.getString("OTT_CONSENT_STATUS", "")).replace("{", "").replace("}", "").replace("\"", ""));
                jSONObject.put("USPrivacy", defaultSharedPreferences.getString(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING, ""));
                SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", bool.toString()))) {
                    fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences3, sharedPreferences3.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z3 = true;
                } else {
                    z3 = false;
                    fVar2 = null;
                }
                new com.onetrust.otpublishers.headless.gpp.b(context);
                if (z3) {
                    sharedPreferences3 = fVar2;
                }
                jSONObject.put("gppString", sharedPreferences3.getBoolean("OT_GPP_IS_ENABLED", false) ? defaultSharedPreferences.getString(OTGppKeys.IAB_GPP_HDR_GPP_STRING, "") : "");
                if (z) {
                    SharedPreferences sharedPreferences4 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                    if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", bool.toString()))) {
                        fVar3 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences4, sharedPreferences4.getString("OT_ACTIVE_PROFILE_ID", ""));
                        z4 = true;
                    } else {
                        fVar3 = null;
                    }
                    if (z4) {
                        sharedPreferences4 = fVar3;
                    }
                    long jLongValue = Long.valueOf(sharedPreferences4.getString("OTT_LAST_GIVEN_CONSENT", "0")).longValue();
                    TimeZone timeZone = TimeZone.getTimeZone("GMT");
                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault(Locale.Category.FORMAT));
                    simpleDateFormat.setTimeZone(timeZone);
                    Date date = new Date();
                    date.setTime(jLongValue);
                    jSONObject.put("consentedDate", simpleDateFormat.format(date));
                    jSONObject.put("addtlString", defaultSharedPreferences.getString(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT, ""));
                    SharedPreferences defaultSharedPreferences2 = PreferenceManager.getDefaultSharedPreferences(context);
                    String string = defaultSharedPreferences2.getString(OTGppKeys.IAB_GPP_TCFEU2_STRING, "");
                    if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                        string = defaultSharedPreferences2.getString("IABTCF_TCString", "");
                    }
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                        str = string;
                    }
                } else {
                    jSONObject.put("consentedDate", "");
                    jSONObject.put("addtlString", "");
                }
                jSONObject.put("tcString", str);
            }
        } catch (JSONException e) {
            Z.p("Error on constructing webviewConsentObject. Error msg = ", e, "WebviewConsentHelper", 6);
        }
        String str2 = "var OTExternalConsent = " + jSONObject.toString();
        K.c("ConsentForWebView :", 3, str2, "WebviewConsentHelper");
        return str2;
    }

    public final void c(JSONObject jSONObject) throws JSONException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_ALWAYS_ACTIVE_GROUPS", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        JSONArray jSONArrayNames = new JSONObject(string).names();
        if (retrofit2.adapter.rxjava3.d.l(jSONArrayNames)) {
            return;
        }
        for (int i = 0; i < jSONArrayNames.length(); i++) {
            String string2 = jSONArrayNames.getString(i);
            if (!string2.startsWith("ISPV2") && !string2.startsWith("ISP2V2") && !string2.startsWith("IFEV2") && !string2.startsWith("IFE2V2")) {
                jSONObject.put(string2, 1);
            }
        }
    }
}
