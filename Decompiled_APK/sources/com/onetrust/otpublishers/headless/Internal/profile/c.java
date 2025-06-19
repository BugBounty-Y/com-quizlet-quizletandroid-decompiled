package com.onetrust.otpublishers.headless.Internal.profile;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3597d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Helper.r;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.e;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProfileSyncParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTRenameProfileParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.onetrust.otpublishers.headless.Public.Response.OTResponseType;
import com.quizlet.quizletandroid.R;
import java.util.Locale;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;
    public final b b;
    public final Context c;

    public c(@NonNull Context context) {
        this.c = context;
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER");
        this.a = dVar;
        this.b = new b(context, dVar);
    }

    public static boolean d(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, String str) throws JSONException {
        String string = dVar.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
        JSONArray jSONArray = new JSONArray();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                jSONArray = new JSONArray(string);
            } catch (JSONException e) {
                Z.p("Error on getting multi-profile id maps. Error = ", e, "MultiprofileConsent", 6);
            }
        }
        Locale locale = Locale.US;
        String lowerCase = str.toLowerCase(locale);
        String lowerCase2 = lowerCase.toLowerCase(locale);
        int i = 0;
        while (true) {
            if (i >= jSONArray.length()) {
                i = -1;
                break;
            }
            if (lowerCase2.equalsIgnoreCase(jSONArray.getString(i))) {
                break;
            }
            i++;
        }
        if (-1 != i) {
            return false;
        }
        OTLogger.c("MultiprofileConsent", 3, "Adding profileID " + lowerCase + " to the profile map.");
        jSONArray.put(lowerCase);
        String string2 = dVar.b().getString("OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP", null);
        JSONObject jSONObject = string2 != null ? new JSONObject(string2) : new JSONObject();
        String string3 = dVar.b().getString("OT_GENERIC_PROFILE_IDENTIFIER", null);
        if (!lowerCase.equalsIgnoreCase(string3)) {
            string3 = UUID.randomUUID().toString();
        }
        jSONObject.put(lowerCase, string3);
        dVar.b().edit().putString("OT_MULTI_PROFILE_ID_MAP", jSONArray.toString()).apply();
        L.i(jSONObject, dVar.b().edit(), "OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP");
        return true;
    }

    public final String a(OTSdkParams oTSdkParams) {
        OTProfileSyncParams otProfileSyncParams;
        if (oTSdkParams != null && (otProfileSyncParams = oTSdkParams.getOtProfileSyncParams()) != null) {
            String identifier = otProfileSyncParams.getIdentifier();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(identifier)) {
                return identifier;
            }
            if (identifier != null && identifier.isEmpty()) {
                return o();
            }
        }
        return this.a.b().getString("OTT_DATA_SUBJECT_IDENTIFIER", null);
    }

    public final void b() {
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = new d(this.c).a;
        String string = dVar.b().getString("OT_MULTI_PROFILE_DELETE_ID", null);
        if (string == null || com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        try {
            i(string);
            OTLogger.c("authenticatedConsentFlow", 4, "Deleting the old profile : ".concat(string));
            dVar.b().edit().remove("OT_MULTI_PROFILE_DELETE_ID").apply();
        } catch (JSONException e) {
            T.d(e, android.support.v4.media.session.a.y("Error on profile delete : ", string, " , error = "), "authenticatedConsentFlow", 6);
        }
    }

    public final void c(String str, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        Context context = this.c;
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = new c(context).a;
        new com.onetrust.otpublishers.headless.Internal.Network.d(context).g(null, AbstractC3597d0.a(dVar), null, null, oTPublishersHeadlessSDK, false);
        new com.onetrust.otpublishers.headless.Internal.Helper.c(context).g(context, dVar.b().getString("OT_IAB_GLOBAL_VENDORLIST", ""));
        com.onetrust.otpublishers.headless.Internal.Helper.a.b(context, dVar.b().getString("OT_GOOGLE_GVL_COMPLETE_OBJECT", null));
        OTLogger.c("MultiprofileConsent", 4, "The user’s profile has been switched successfully. Profile switched to : " + str);
    }

    public final boolean e(OTRenameProfileParams oTRenameProfileParams) {
        boolean z;
        String string;
        String oldProfileID = oTRenameProfileParams.getOldProfileID();
        if (com.onetrust.otpublishers.headless.Internal.a.j(oldProfileID)) {
            OTLogger.c("OneTrust", 5, "Empty oldProfileID passed,  using the generic profile Id as oldProfileID.");
            oldProfileID = m();
            oTRenameProfileParams = OTRenameProfileParams.OTRenameProfileParamsBuilder.newInstance().setOldProfileID(oldProfileID).setNewProfileID(oTRenameProfileParams.getNewProfileID()).setIdentifierType(oTRenameProfileParams.getIdentifierType()).build();
        }
        String newProfileID = oTRenameProfileParams.getNewProfileID();
        if (com.onetrust.otpublishers.headless.Internal.a.j(oldProfileID)) {
            OTLogger.c("OneTrust", 5, "Empty oldProfileID passed,  and no Active profile exist. Rename profile failed.");
        } else {
            if (!com.onetrust.otpublishers.headless.Internal.a.j(newProfileID)) {
                z = true;
                string = this.a.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
                if (z && !com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                    try {
                        return f(oTRenameProfileParams, string);
                    } catch (JSONException e) {
                        Z.p("JSON error on renameProfile. Error = ", e, "MultiprofileConsent", 6);
                    }
                }
                return false;
            }
            OTLogger.c("OneTrust", 5, "Empty newProfileID passed,  Please pass a valid user ID to update.");
        }
        z = false;
        string = this.a.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
        if (z) {
            return f(oTRenameProfileParams, string);
        }
        return false;
    }

    public final boolean f(OTRenameProfileParams oTRenameProfileParams, String str) throws JSONException {
        boolean z;
        boolean z2;
        boolean z3;
        Context context = this.c;
        JSONArray jSONArray = new JSONArray(str);
        String oldProfileID = oTRenameProfileParams.getOldProfileID();
        String newProfileID = oTRenameProfileParams.getNewProfileID();
        String lowerCase = oldProfileID.toLowerCase(Locale.US);
        int i = 0;
        while (true) {
            if (i >= jSONArray.length()) {
                i = -1;
                break;
            }
            if (lowerCase.equalsIgnoreCase(jSONArray.getString(i))) {
                break;
            }
            i++;
        }
        if (-1 != i) {
            z = true;
        } else {
            OTLogger.c("MultiprofileConsent", 5, "No user profile found with ID " + oldProfileID + ". Please pass a valid user ID to update");
            z = false;
        }
        String lowerCase2 = newProfileID.toLowerCase(Locale.US);
        int i2 = 0;
        while (true) {
            if (i2 >= jSONArray.length()) {
                i2 = -1;
                break;
            }
            if (lowerCase2.equalsIgnoreCase(jSONArray.getString(i2))) {
                break;
            }
            i2++;
        }
        if (-1 != i2) {
            OTLogger.c("MultiprofileConsent", 5, "Two users cannot have the same user ID " + newProfileID + ". Thus, pass a unique user ID");
            z2 = false;
        } else {
            z2 = true;
        }
        if (z && z2) {
            OTLogger.c("MultiprofileConsent", 5, AbstractC0147y.e("Renaming profile ID from  ", oldProfileID, " , to ", newProfileID, " ."));
            String strM = m();
            com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
            String string = dVar.b().getString("OT_GENERIC_PROFILE_IDENTIFIER", null);
            String string2 = dVar.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
            JSONArray jSONArray2 = new JSONArray();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                try {
                    jSONArray2 = new JSONArray(string2);
                } catch (JSONException e) {
                    Z.p("Error on getting multi-profile id maps. Error = ", e, "MultiprofileConsent", 6);
                }
            }
            Locale locale = Locale.US;
            String lowerCase3 = newProfileID.toLowerCase(locale);
            String lowerCase4 = lowerCase3.toLowerCase(locale);
            int i3 = 0;
            while (true) {
                if (i3 >= jSONArray2.length()) {
                    i3 = -1;
                    break;
                }
                if (lowerCase4.equalsIgnoreCase(jSONArray2.getString(i3))) {
                    break;
                }
                i3++;
            }
            if (-1 != i3) {
                z3 = false;
            } else {
                String strN = n(oldProfileID.toLowerCase(locale));
                k(oldProfileID);
                OTLogger.c("MultiprofileConsent", 3, "Adding profileID " + lowerCase3 + " to the profile map.");
                jSONArray2.put(lowerCase3);
                String string3 = dVar.b().getString("OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP", null);
                JSONObject jSONObject = string3 != null ? new JSONObject(string3) : new JSONObject();
                jSONObject.put(lowerCase3, strN);
                dVar.b().edit().putString("OT_MULTI_PROFILE_ID_MAP", jSONArray2.toString()).apply();
                L.i(jSONObject, dVar.b().edit(), "OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP");
                z3 = true;
            }
            if (z3) {
                String oldProfileID2 = oTRenameProfileParams.getOldProfileID();
                String newProfileID2 = oTRenameProfileParams.getNewProfileID();
                if (oldProfileID2.equalsIgnoreCase(strM)) {
                    this.b.a(newProfileID2);
                }
                if (oldProfileID2.equalsIgnoreCase(string)) {
                    u("");
                }
                try {
                    r rVar = new r(context);
                    e eVar = rVar.b;
                    rVar.a(context, newProfileID2);
                    eVar.c(2);
                    String identifierType = oTRenameProfileParams.getIdentifierType();
                    com.onetrust.otpublishers.headless.Internal.Preferences.d dVar2 = eVar.a;
                    if (com.onetrust.otpublishers.headless.Internal.a.j(identifierType)) {
                        dVar2.getClass();
                    } else {
                        dVar2.b().edit().putString("OTT_IDENTIFIER_TYPE", identifierType).apply();
                    }
                    return true;
                } catch (JSONException e2) {
                    Z.p("error in updating consent : ", e2, "MultiprofileConsent", 6);
                }
            }
        }
        return false;
    }

    public final boolean g(OTCallback oTCallback, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, String str, String str2, String str3, boolean z) {
        boolean zI;
        String lowerCase = str.toLowerCase(Locale.US);
        try {
            zI = i(lowerCase);
        } catch (JSONException e) {
            T.d(e, android.support.v4.media.session.a.y("Exception on profile delete for id = ", lowerCase, " . Exception = "), "MultiprofileConsent", 6);
            zI = false;
        }
        Context context = this.c;
        if (zI) {
            com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
            if (lowerCase.equalsIgnoreCase(dVar.b().getString("OT_GENERIC_PROFILE_IDENTIFIER", null))) {
                u("");
            }
            if (lowerCase.equalsIgnoreCase(m())) {
                dVar.b().edit().putString("OT_ACTIVE_PROFILE_ID", "".toLowerCase(Locale.US)).apply();
                l(oTCallback, oTPublishersHeadlessSDK, o(), str2, str3, z);
            } else if (oTCallback != null) {
                oTCallback.onSuccess(new OTResponse(OTResponseType.OT_SUCCESS, 14, context.getResources().getString(R.string.ott_profile_delete_profile_success), ""));
            }
        } else if (oTCallback != null) {
            oTCallback.onFailure(new OTResponse(OTResponseType.OT_ERROR, 13, context.getResources().getString(R.string.ott_profile_delete_profile_error), ""));
        }
        return zI;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005d A[Catch: Exception -> 0x0039, TRY_LEAVE, TryCatch #0 {Exception -> 0x0039, blocks: (B:9:0x0027, B:11:0x0033, B:18:0x0057, B:20:0x005d, B:17:0x0052, B:16:0x003c), top: B:42:0x0027, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0067  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean h(com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r10, com.onetrust.otpublishers.headless.Public.OTCallback r11) {
        /*
            Method dump skipped, instructions count: 259
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.profile.c.h(com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK, com.onetrust.otpublishers.headless.Public.OTCallback):boolean");
    }

    public final boolean i(String str) {
        String strB;
        String lowerCase = str.toLowerCase(Locale.US);
        String strP = p(lowerCase);
        boolean z = true;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(strP)) {
            String strD = AbstractC0147y.d("com.onetrust.otpublishers.headless.preference.OTT_USER_", strP);
            Context context = this.c;
            context.getSharedPreferences(strD, 0).edit().clear().apply();
            if (context.deleteSharedPreferences(strD)) {
                OTLogger.c("MultiprofileConsent", 4, "Profile file " + strD + " deleted.");
                strB = android.support.v4.media.session.a.B("Profile ", lowerCase, " deleted.");
            } else {
                OTLogger.c("MultiprofileConsent", 4, "Failed to delete profile file " + strD + " .");
                strB = android.support.v4.media.session.a.B("Failed to delete profile ", lowerCase, " .");
                z = false;
            }
            OTLogger.c("MultiprofileConsent", 4, strB);
        }
        k(lowerCase);
        return z;
    }

    public final void j() {
        OTLogger.c("multiProfileEnabled", 3, "enableMultiProfile called.");
        this.a.b().edit().putString("OT_ENABLE_MULTI_PROFILE", Boolean.TRUE.toString()).apply();
    }

    public final void k(String str) {
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        String string = dVar.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
        String string2 = dVar.b().getString("OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string) || com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
            return;
        }
        JSONArray jSONArray = new JSONArray(string);
        JSONObject jSONObject = new JSONObject(string2);
        String lowerCase = str.toLowerCase(Locale.US);
        int i = 0;
        while (true) {
            if (i >= jSONArray.length()) {
                i = -1;
                break;
            } else if (lowerCase.equalsIgnoreCase(jSONArray.getString(i))) {
                break;
            } else {
                i++;
            }
        }
        if (-1 != i) {
            jSONObject.remove(jSONArray.getString(i));
            jSONArray.remove(i);
            dVar.b().edit().putString("OT_MULTI_PROFILE_ID_MAP", jSONArray.toString()).apply();
            L.i(jSONObject, dVar.b().edit(), "OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0062 A[Catch: Exception -> 0x003f, TRY_LEAVE, TryCatch #1 {Exception -> 0x003f, blocks: (B:9:0x002d, B:11:0x0039, B:18:0x005c, B:20:0x0062, B:17:0x0057, B:16:0x0042), top: B:79:0x002d, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean l(com.onetrust.otpublishers.headless.Public.OTCallback r17, com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r18, java.lang.String r19, java.lang.String r20, java.lang.String r21, boolean r22) {
        /*
            Method dump skipped, instructions count: 547
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.profile.c.l(com.onetrust.otpublishers.headless.Public.OTCallback, com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK, java.lang.String, java.lang.String, java.lang.String, boolean):boolean");
    }

    public final String m() {
        return this.a.b().getString("OT_ACTIVE_PROFILE_ID", "");
    }

    public final String n(String str) throws JSONException {
        String strP = p(str);
        return strP != null ? strP : o();
    }

    public final String o() {
        String string = this.a.b().getString("OT_GENERIC_PROFILE_IDENTIFIER", null);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return string;
        }
        String string2 = UUID.randomUUID().toString();
        u(string2);
        return string2;
    }

    public final String p(String str) throws JSONException {
        String string = this.a.b().getString("OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP", null);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                String string2 = new JSONObject(string).getString(str);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    return string2;
                }
            } catch (JSONException e) {
                Z.p("Error on profile ID file name map. Error = ", e, "MultiprofileConsent", 6);
            }
        }
        Context context = this.c;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        String string3 = sharedPreferences.getString("OT_MULTI_PROFILE_ID_MAP", null);
        String string4 = sharedPreferences.getString("OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP", null);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string3) && com.onetrust.otpublishers.headless.Internal.a.j(string4) && context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0).getLong("OT_SDK_VERSION_CODE", 0L) < 63900) {
            try {
                context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + str, 0);
                return str;
            } catch (IllegalArgumentException e2) {
                OTLogger.c("MultiprofileConsent", 6, "Error on file creation, file name = " + str);
                OTLogger.c("MultiprofileConsent", 6, "Error on file creation, error = " + e2.getMessage());
            }
        }
        return null;
    }

    public final int q() {
        String string = this.a.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return -1;
        }
        try {
            return new JSONArray(string).length();
        } catch (JSONException e) {
            Z.p("Error on getting profilemap JSON. Error = ", e, "MultiprofileConsent", 6);
            return -1;
        }
    }

    public final boolean r(String str) {
        if (str == null) {
            return false;
        }
        String string = this.a.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                JSONArray jSONArray = new JSONArray(string);
                String lowerCase = str.toLowerCase(Locale.US);
                int i = 0;
                while (true) {
                    if (i >= jSONArray.length()) {
                        i = -1;
                        break;
                    }
                    if (lowerCase.equalsIgnoreCase(jSONArray.getString(i))) {
                        break;
                    }
                    i++;
                }
                return true ^ (-1 != i);
            } catch (JSONException e) {
                Z.p("Error on getting profilemap. Error = ", e, "MultiprofileConsent", 6);
            }
        }
        return false;
    }

    public final int s(String str) {
        String strM = m();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(strM) && strM.equalsIgnoreCase(str)) {
            return 0;
        }
        boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(str);
        b bVar = this.b;
        if (!zJ) {
            bVar.b(strM, str, true, true);
            return 1;
        }
        if (str == null && com.onetrust.otpublishers.headless.Internal.a.j(strM)) {
            bVar.b(strM, o(), false, false);
            return 2;
        }
        if (str == null && !com.onetrust.otpublishers.headless.Internal.a.j(strM)) {
            return 3;
        }
        if (str == null || !str.isEmpty()) {
            return -1;
        }
        bVar.b(strM, o(), true, true);
        return 4;
    }

    public final boolean t() {
        return Z.r(Boolean.FALSE, this.a.b(), "OT_ENABLE_MULTI_PROFILE");
    }

    public final void u(String str) {
        this.a.b().edit().putString("OT_GENERIC_PROFILE_IDENTIFIER", str).apply();
    }
}
