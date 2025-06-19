package com.onetrust.otpublishers.headless.Internal.profile;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;

    public d(@NonNull Context context) {
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER");
    }

    public final void a(String str) throws JSONException {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        JSONObject jSONObject = new JSONObject(str);
        if (jSONObject.has("culture")) {
            JSONObject jSONObject2 = jSONObject.getJSONObject("culture");
            if (jSONObject2.has("MobileData")) {
                JSONObject jSONObject3 = jSONObject2.getJSONObject("MobileData");
                if (jSONObject3.has("multiProfileConsent")) {
                    JSONObject jSONObject4 = jSONObject3.getJSONObject("multiProfileConsent");
                    boolean zOptBoolean = jSONObject4.optBoolean("isEnabled", false);
                    boolean zOptBoolean2 = jSONObject4.optBoolean("downloadDataAfterSwitch", false);
                    int iOptInt = jSONObject4.optInt("maxProfilesLimit", 6);
                    OTLogger.c("MultiprofileConsent", 3, "Multiprofile consent isEnabled = " + zOptBoolean + ", downloadAfterSwitch = " + zOptBoolean2 + " , maximumProfileLimit = " + iOptInt);
                    SharedPreferences.Editor editorEdit = this.a.b().edit();
                    editorEdit.putBoolean("OT_MULTI_PROFILE_CONSENT_ENABLED", zOptBoolean);
                    editorEdit.putBoolean("OT_MULTI_PROFILE_DOWNLOAD_DATA_AFTER_SWITCH", zOptBoolean2);
                    editorEdit.putInt("OT_MULTI_PROFILE_MAXIMUM_PROFILES_LIMIT", iOptInt);
                    editorEdit.apply();
                }
            }
        }
    }
}
