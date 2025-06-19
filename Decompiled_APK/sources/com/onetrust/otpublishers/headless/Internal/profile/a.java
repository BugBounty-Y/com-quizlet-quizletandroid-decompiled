package com.onetrust.otpublishers.headless.Internal.profile;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import java.util.HashMap;
import java.util.Locale;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;

    public a(@NonNull Context context) {
        this.a = context;
    }

    public final void a(SharedPreferences sharedPreferences, SharedPreferences.Editor editor, SharedPreferences.Editor editor2) {
        HashMap map = new com.onetrust.otpublishers.headless.gpp.b(this.a).b;
        if (map.keySet().isEmpty()) {
            return;
        }
        for (String str : map.keySet()) {
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                Integer num = (Integer) map.get(str);
                if (Objects.equals(num, 10)) {
                    if (sharedPreferences.contains(str)) {
                        editor.putInt(str, sharedPreferences.getInt(str, -1));
                        if (editor2 != null) {
                            editor2.remove(str);
                        }
                    }
                } else if (Objects.equals(num, 30) && sharedPreferences.contains(str)) {
                    editor.putString(str, sharedPreferences.getString(str, ""));
                    if (editor2 != null) {
                        editor2.remove(str);
                    }
                }
            }
        }
    }

    public final void b(SharedPreferences sharedPreferences, SharedPreferences.Editor editor, SharedPreferences.Editor editor2, boolean z, boolean z2, boolean z3, boolean z4) {
        if (z) {
            if (sharedPreferences.contains("IABTCF_CmpSdkID")) {
                editor.putInt("IABTCF_CmpSdkID", sharedPreferences.getInt("IABTCF_CmpSdkID", -1));
                if (editor2 != null) {
                    editor2.remove("IABTCF_CmpSdkID");
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_CMPSDKVERSION)) {
                editor.putInt(OTIABTCFKeys.IABTCF_CMPSDKVERSION, sharedPreferences.getInt(OTIABTCFKeys.IABTCF_CMPSDKVERSION, -1));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_CMPSDKVERSION);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_POLICYVERSION)) {
                editor.putInt(OTIABTCFKeys.IABTCF_POLICYVERSION, sharedPreferences.getInt(OTIABTCFKeys.IABTCF_POLICYVERSION, -1));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_POLICYVERSION);
                }
            }
            if (sharedPreferences.contains("IABTCF_gdprApplies")) {
                editor.putInt("IABTCF_gdprApplies", sharedPreferences.getInt("IABTCF_gdprApplies", -1));
                if (editor2 != null) {
                    editor2.remove("IABTCF_gdprApplies");
                }
            }
            if (sharedPreferences.contains("IABTCF_PurposeOneTreatment")) {
                editor.putInt("IABTCF_PurposeOneTreatment", sharedPreferences.getInt("IABTCF_PurposeOneTreatment", -1));
                if (editor2 != null) {
                    editor2.remove("IABTCF_PurposeOneTreatment");
                }
            }
            if (sharedPreferences.contains("IABTCF_PublisherCC")) {
                editor.putString("IABTCF_PublisherCC", sharedPreferences.getString("IABTCF_PublisherCC", ""));
                if (editor2 != null) {
                    editor2.remove("IABTCF_PublisherCC");
                }
            }
            if (sharedPreferences.contains("IABTCF_PublisherCC")) {
                editor.putString("IABTCF_PublisherCC", sharedPreferences.getString("IABTCF_PublisherCC", ""));
                if (editor2 != null) {
                    editor2.remove("IABTCF_PublisherCC");
                }
            }
            if (sharedPreferences.contains("IABTCF_TCString")) {
                editor.putString("IABTCF_TCString", sharedPreferences.getString("IABTCF_TCString", ""));
                if (editor2 != null) {
                    editor2.remove("IABTCF_TCString");
                }
            }
            if (sharedPreferences.contains("IABTCF_VendorConsents")) {
                editor.putString("IABTCF_VendorConsents", sharedPreferences.getString("IABTCF_VendorConsents", ""));
                if (editor2 != null) {
                    editor2.remove("IABTCF_VendorConsents");
                }
            }
            if (sharedPreferences.contains("IABTCF_VendorLegitimateInterests")) {
                editor.putString("IABTCF_VendorLegitimateInterests", sharedPreferences.getString("IABTCF_VendorLegitimateInterests", ""));
                if (editor2 != null) {
                    editor2.remove("IABTCF_VendorLegitimateInterests");
                }
            }
            if (sharedPreferences.contains("IABTCF_PurposeConsents")) {
                editor.putString("IABTCF_PurposeConsents", sharedPreferences.getString("IABTCF_PurposeConsents", ""));
                if (editor2 != null) {
                    editor2.remove("IABTCF_PurposeConsents");
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS)) {
                editor.putString(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS, sharedPreferences.getString(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS)) {
                editor.putString(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS, sharedPreferences.getString(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_PUBLISHERCONSENT)) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCONSENT, sharedPreferences.getString(OTIABTCFKeys.IABTCF_PUBLISHERCONSENT, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_PUBLISHERCONSENT);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_PUBLISHERLEGITIMATEINTERESTS)) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERLEGITIMATEINTERESTS, sharedPreferences.getString(OTIABTCFKeys.IABTCF_PUBLISHERLEGITIMATEINTERESTS, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_PUBLISHERLEGITIMATEINTERESTS);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS)) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS, sharedPreferences.getString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS)) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS, sharedPreferences.getString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT)) {
                editor.putString(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT, sharedPreferences.getString(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT, ""));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT);
                }
            }
            for (int i = 1; i <= 11; i++) {
                String strD = AbstractC0147y.d(OTIABTCFKeys.IABTCF_PUBLISHERRESTRICTIONS, String.valueOf(i));
                if (sharedPreferences.contains(strD)) {
                    editor.putString(strD, sharedPreferences.getString(strD, ""));
                    if (editor2 != null) {
                        editor2.remove(strD);
                    }
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS)) {
                editor.putInt(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS, sharedPreferences.getInt(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS, -1));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS);
                }
            }
            if (sharedPreferences.contains(OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS)) {
                editor.putInt(OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS, sharedPreferences.getInt(OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS, -1));
                if (editor2 != null) {
                    editor2.remove(OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS);
                }
            }
        }
        if (z2 && sharedPreferences.contains(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING)) {
            editor.putString(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING, sharedPreferences.getString(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING, ""));
            if (editor2 != null) {
                editor2.remove(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING);
            }
        }
        if (z3) {
            a(sharedPreferences, editor, editor2);
            return;
        }
        if (z4) {
            HashMap map = new com.onetrust.otpublishers.headless.gpp.b(this.a).b;
            if (map.keySet().isEmpty()) {
                return;
            }
            for (String str : map.keySet()) {
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && !com.onetrust.otpublishers.headless.Internal.a.j(str) && str.startsWith("IABGPP_TCFEU2_")) {
                    Integer num = (Integer) map.get(str);
                    if (Objects.equals(num, 10)) {
                        if (sharedPreferences.contains(str)) {
                            editor.putInt(str, sharedPreferences.getInt(str, -1));
                        }
                    } else if (Objects.equals(num, 30) && sharedPreferences.contains(str)) {
                        editor.putString(str, sharedPreferences.getString(str, ""));
                    }
                }
            }
        }
    }

    public final void c(String str, boolean z, boolean z2, boolean z3) {
        if (z) {
            K.c("Restore of default shared preference data, profile id = ", 3, str, "DefaultSPHelper");
            Context context = this.a;
            SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new c(context).n(str.toLowerCase(Locale.US)), 0);
            SharedPreferences.Editor editorEdit = defaultSharedPreferences.edit();
            b(sharedPreferences, editorEdit, null, true, z2, z3, false);
            if (z3) {
                a(sharedPreferences, editorEdit, null);
            }
            editorEdit.apply();
        }
    }

    public final void d(String str, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6) {
        if (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("DefaultSPHelper", 3, "backupData called with empty currentActiveProfileId, back up failed.");
            return;
        }
        if (z) {
            OTLogger.c("DefaultSPHelper", 3, "Taking backup of default shared preference data, profile id = ".concat(str));
            OTLogger.c("DefaultSPHelper", 3, "Clearing default shared preference keys after the back up completes. Flag = " + z2);
            Context context = this.a;
            SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            SharedPreferences.Editor editorEdit = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new c(context).n(str.toLowerCase(Locale.US)), 0).edit();
            SharedPreferences.Editor editorEdit2 = z2 ? defaultSharedPreferences.edit() : null;
            b(defaultSharedPreferences, editorEdit, editorEdit2, z3, z4, z5, z6);
            editorEdit.apply();
            if (editorEdit2 != null) {
                editorEdit2.apply();
            }
        }
    }
}
