package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.SharedPreferences;
import com.onetrust.otpublishers.headless.gcm.consent.OTGCMConsentStatus;
import java.util.Locale;
import kotlin.text.C4962a;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.r4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3712r4 {
    public static final /* synthetic */ int a = 0;

    public static OTGCMConsentStatus a(Context context, JSONObject jSONObject, String str, String str2) throws JSONException {
        boolean zEqualsIgnoreCase;
        boolean zHas;
        int i;
        if (!jSONObject.has(str)) {
            return OTGCMConsentStatus.UNDEFINED;
        }
        String string = jSONObject.getString(str);
        if (string != null) {
            zEqualsIgnoreCase = string.equalsIgnoreCase("DNAC");
        } else if (string != "DNAC") {
            if (string != null && string.length() == 4) {
                int length = string.length();
                for (int i2 = 0; i2 < length; i2++) {
                    if (C4962a.a(string.charAt(i2), "DNAC".charAt(i2), true)) {
                    }
                }
                zEqualsIgnoreCase = true;
            }
            zEqualsIgnoreCase = false;
            break;
        } else {
            zEqualsIgnoreCase = true;
        }
        if (!zEqualsIgnoreCase) {
            String string2 = jSONObject.getString(str);
            if (!(string2 == null || string2.length() == 0)) {
                String string3 = jSONObject.getString(str);
                if (com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                    zHas = false;
                } else {
                    Locale locale = Locale.ENGLISH;
                    zHas = new JSONObject(str2.toLowerCase(locale)).has(string3.toLowerCase(locale));
                }
                if (!zHas) {
                    return OTGCMConsentStatus.UNDEFINED;
                }
                JSONObject jSONObject2 = new JSONObject();
                new JSONObject();
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Q.a(context)) {
                    SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
                    sharedPreferences.edit();
                    sharedPreferences2.edit();
                }
                com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
                new JSONObject();
                new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
                new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
                try {
                    i = jSONObject2.has(string3) ? jSONObject2.getInt(string3) : eVar.a(string3);
                } catch (JSONException e) {
                    com.google.android.gms.measurement.internal.Z.p("Error while getting updated value of Purpose Consent ", e, "CustomGroupDetails", 6);
                    i = -1;
                }
                return i == 1 ? OTGCMConsentStatus.GRANTED : OTGCMConsentStatus.DENIED;
            }
        }
        return OTGCMConsentStatus.UNASSIGNED;
    }
}
