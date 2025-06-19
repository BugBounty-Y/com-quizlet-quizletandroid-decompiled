package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class t {
    public String a;

    public t(@NonNull Context context) {
    }

    public static void a(boolean z, boolean z2, com.onetrust.otpublishers.headless.Internal.Preferences.e eVar) throws JSONException {
        String str;
        String strB;
        boolean z3 = ((com.onetrust.otpublishers.headless.Internal.Preferences.d) eVar.b.b).b().getBoolean("OT_GENERAL_VENDORS_CONFIGURED", false);
        com.google.mlkit.vision.documentscanner.internal.c cVar = eVar.b;
        boolean z4 = ((com.onetrust.otpublishers.headless.Internal.Preferences.d) cVar.b).b().getBoolean("OT_GENERAL_VENDORS_TOGGLE_CONFIGURED", false);
        if (z3 && z4) {
            JSONObject jSONObjectA = cVar.a();
            new JSONObject();
            JSONArray jSONArrayNames = jSONObjectA.names();
            if (retrofit2.adapter.rxjava3.d.l(jSONArrayNames)) {
                jSONObjectA = null;
            } else {
                for (int i = 0; i < jSONArrayNames.length(); i++) {
                    String string = jSONArrayNames.getString(i);
                    if (jSONObjectA.has(string)) {
                        try {
                            JSONObject jSONObject = jSONObjectA.getJSONObject(string);
                            int iOptInt = jSONObject.optInt(OTVendorUtils.CONSENT_TYPE, -1);
                            if (-1 != iOptInt && 2 != iOptInt) {
                                jSONObject.put(OTVendorUtils.CONSENT_TYPE, String.valueOf(z ? 1 : 0));
                                OTLogger.c("GeneralVendors", 4, "Consent updated for Vendor: " + string + " as " + z);
                            }
                        } catch (JSONException e) {
                            strB = "error while updating Vendor status:" + e;
                        }
                    } else {
                        strB = android.support.v4.media.session.a.B("Given Vendor ID ", string, " does not match with any existing vendors. Please check and pass the correct Vendor ID");
                    }
                    OTLogger.c("GeneralVendors", 6, strB);
                }
            }
            if (z2) {
                OTLogger.c("GeneralVendors", 4, "General Vendors saved as :" + jSONObjectA);
                return;
            } else {
                if (jSONObjectA == null) {
                    return;
                }
                ((com.onetrust.otpublishers.headless.Internal.Preferences.d) cVar.b).b().edit().putString("OT_GENERAL_VENDORS", jSONObjectA.toString()).apply();
                str = "General Vendors saved as :" + jSONObjectA;
            }
        } else {
            if (z4) {
                OTLogger.c("GeneralVendors", 3, "General Vendors consent not saved : No Vendors configured");
                return;
            }
            str = "General Vendors consent not saved : Vendor Opt-out disabled from admin settings";
        }
        OTLogger.c("GeneralVendors", 4, str);
    }
}
