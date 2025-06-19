package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTBroadcastServiceKeys;
import com.onetrust.otpublishers.headless.Public.OTConsentInteractionType;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class o {
    public final Context a;

    public o(Context context) {
        this.a = context;
    }

    public final void a(int i, String str) {
        OTLogger.c("OTConsentChanges", 4, "Sending " + str + " broadcast, value = " + i);
        Intent intent = new Intent(str);
        intent.putExtra(OTBroadcastServiceKeys.EVENT_STATUS, i);
        Context context = this.a;
        intent.setPackage(context.getApplicationContext().getPackageName());
        context.sendBroadcast(intent);
    }

    public final void b(String str) {
        if (OTConsentInteractionType.BANNER_BACK.equalsIgnoreCase(str) || OTConsentInteractionType.PC_CLOSE.equalsIgnoreCase(str) || OTConsentInteractionType.UC_PC_CONFIRM.equalsIgnoreCase(str)) {
            K.c("Not sending OTConsentUpdated broadcast. Interaction type = ", 3, str, "OTConsentChanges");
            return;
        }
        OTLogger.c("OTConsentChanges", 4, "Sending OTConsentUpdated action broadcast. Interaction type = ".concat(str));
        Intent intent = new Intent();
        intent.setAction(OTBroadcastServiceKeys.OT_CONSENT_UPDATED);
        Context context = this.a;
        intent.setPackage(context.getApplicationContext().getPackageName());
        context.sendBroadcast(intent);
    }

    public final void c(JSONObject jSONObject) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        Context context = this.a;
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
        String string = sharedPreferences.getString("OT_GROUP_ID_OBJECT", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        try {
            JSONObject jSONObject2 = new JSONObject(string);
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                int i = jSONObject.getInt(next);
                if (jSONObject2.has(next)) {
                    a(i, next);
                }
            }
        } catch (JSONException e) {
            OTLogger.c("OTConsentChanges", 6, "error in broadcasting status. err = " + e.getMessage() + " changedConsents = " + jSONObject.toString());
        }
    }
}
