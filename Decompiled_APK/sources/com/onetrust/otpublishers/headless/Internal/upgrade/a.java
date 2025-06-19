package com.onetrust.otpublishers.headless.Internal.upgrade;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.e;
import com.onetrust.otpublishers.headless.Internal.profile.c;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import com.quizlet.quizletandroid.R;
import java.util.Locale;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;

    public a(@NonNull Context context) {
        this.a = context;
    }

    public final void a() throws JSONException {
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        String string = sharedPreferences.getString("OT_MULTI_PROFILE_ID_MAP", null);
        String string2 = sharedPreferences.getString("OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string) || !com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
            return;
        }
        SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        JSONArray jSONArray = new JSONArray(sharedPreferences2.getString("OT_MULTI_PROFILE_ID_MAP", null));
        JSONObject jSONObject = new JSONObject();
        for (int i = 0; i < jSONArray.length(); i++) {
            String string3 = jSONArray.getString(i);
            try {
                context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + string3, 0);
                jSONObject.put(string3, string3);
            } catch (IllegalArgumentException e) {
                OTLogger.c("OneTrust", 6, "Error on file creation, file name = " + string3);
                OTLogger.c("OneTrust", 6, "Error on file creation, error = " + e.getMessage());
                jSONObject.put(string3, UUID.randomUUID().toString());
            }
        }
        L.i(jSONObject, sharedPreferences2.edit(), "OT_MULTI_PROFILE_PROFILE_ID_FILE_MAP");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0062 A[Catch: Exception -> 0x003e, TRY_LEAVE, TryCatch #0 {Exception -> 0x003e, blocks: (B:9:0x002c, B:11:0x0038, B:18:0x005c, B:20:0x0062, B:17:0x0057, B:16:0x0041), top: B:154:0x002c, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.content.SharedPreferences r25) {
        /*
            Method dump skipped, instructions count: 899
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.upgrade.a.b(android.content.SharedPreferences):void");
    }

    public final void c() {
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (!sharedPreferences.contains("OT_SDK_VERSION_CODE") || Long.parseLong(context.getString(R.string.ot_sdk_version_code)) > sharedPreferences.getLong("OT_SDK_VERSION_CODE", 0L)) {
            try {
                SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                long j = Long.parseLong(context.getString(R.string.ot_sdk_version_code));
                long j2 = sharedPreferences2.getLong("OT_SDK_VERSION_CODE", 0L);
                if (j2 < 63500) {
                    if (1 == sharedPreferences2.getInt("OTT_DATA_SUBJECT_IDENTIFIER_TYPE", 1)) {
                        String string = sharedPreferences2.getString("OTT_DATA_SUBJECT_IDENTIFIER", null);
                        if (!com.onetrust.otpublishers.headless.Internal.a.j(string) && !sharedPreferences2.contains("OT_GENERIC_PROFILE_IDENTIFIER")) {
                            context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).edit().putString("OT_GENERIC_PROFILE_IDENTIFIER", string).apply();
                        }
                    }
                    b(sharedPreferences2);
                }
                if (j2 < 202310100 && new e(context).m()) {
                    e();
                }
                if (j2 < 202402100) {
                    d(sharedPreferences2);
                }
                OTLogger.c("OTSDKUpgrade", 3, "Setting SDK version code = " + j);
                sharedPreferences2.edit().putLong("OT_SDK_VERSION_CODE", j).apply();
            } catch (Exception e) {
                Z.n("Error on handleSDKUpgradeIfNeeded,Error = ", e, "OTSDKExceptions", 6);
            }
        }
        try {
            a();
        } catch (JSONException unused) {
            OTLogger.c("OneTrust", 6, "Error on handling upgrade case for multiprofile file name change.");
        }
    }

    public final void d(SharedPreferences sharedPreferences) {
        boolean z;
        String strConcat = "com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER");
        Context context = this.a;
        String string = context.getSharedPreferences(strConcat, 0).getString("OT_ACTIVE_PROFILE_ID", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new c(context).n(string.toLowerCase(Locale.US)), 0);
        SharedPreferences.Editor editorEdit = sharedPreferences2.edit();
        boolean z2 = true;
        if (!sharedPreferences.contains("OT_GPP_DATA_BACKUP") || sharedPreferences2.contains("OT_GPP_DATA_BACKUP")) {
            z = false;
        } else {
            editorEdit.putString("OT_GPP_DATA_BACKUP", sharedPreferences.getString("OT_GPP_DATA_BACKUP", ""));
            z = true;
        }
        if (!sharedPreferences.contains("OT_GPP_IS_ENABLED") || sharedPreferences2.contains("OT_GPP_IS_ENABLED")) {
            z2 = z;
        } else {
            editorEdit.putBoolean("OT_GPP_IS_ENABLED", sharedPreferences.getBoolean("OT_GPP_IS_ENABLED", false));
        }
        if (z2) {
            editorEdit.apply();
        }
    }

    public final void e() {
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this.a);
        SharedPreferences.Editor editorEdit = defaultSharedPreferences.edit();
        if (defaultSharedPreferences.contains(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS)) {
            OTLogger.c("UpgradeHelper", 3, "Migrating IABTCF_USENONSTANDARDSTACKS - > IABTCF_USENONSTANDARDTEXTS");
            int i = defaultSharedPreferences.getInt(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS, 0);
            editorEdit.remove(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS);
            editorEdit.putInt(OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS, i);
            editorEdit.apply();
        }
        if (defaultSharedPreferences.contains(OTGppKeys.IAB_GPP_USENONSTANDARDSTACKS)) {
            OTLogger.c("UpgradeHelper", 3, "Migrating IAB_GPP_USENONSTANDARDSTACKS - > IAB_GPP_USENONSTANDARDTEXTS");
            int i2 = defaultSharedPreferences.getInt(OTGppKeys.IAB_GPP_USENONSTANDARDSTACKS, 0);
            editorEdit.remove(OTGppKeys.IAB_GPP_USENONSTANDARDSTACKS);
            editorEdit.putInt(OTGppKeys.IAB_GPP_USENONSTANDARDTEXTS, i2);
            editorEdit.apply();
        }
    }
}
