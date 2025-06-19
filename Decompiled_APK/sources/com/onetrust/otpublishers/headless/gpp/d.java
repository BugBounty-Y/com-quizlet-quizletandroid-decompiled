package com.onetrust.otpublishers.headless.gpp;

import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import java.util.HashMap;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public final Context a;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d b;

    public d(Context context) {
        this.a = context;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
    }

    public static StringBuilder b(HashMap map, String[] strArr) {
        StringBuilder sb = new StringBuilder();
        for (String str : strArr) {
            Integer num = (Integer) map.get(str);
            if (num != null) {
                sb.append(e.a(num.intValue(), 2));
            }
        }
        return sb;
    }

    public final int a(String str) {
        int i;
        if (!c(str)) {
            return 0;
        }
        JSONObject jSONObject = new JSONObject();
        new JSONObject();
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            new com.onetrust.otpublishers.headless.Internal.Preferences.c(sharedPreferences, context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", "")), 0));
        }
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        new JSONObject();
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        try {
            i = jSONObject.has(str) ? jSONObject.getInt(str) : eVar.a(str);
        } catch (JSONException e) {
            Z.p("Error while getting updated value of Purpose Consent ", e, "CustomGroupDetails", 6);
            i = -1;
        }
        return i == 1 ? 2 : 1;
    }

    public final boolean c(String str) {
        boolean zHas;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            String string = this.b.b().getString("OT_UI_VALID_GROUP_IDS", "");
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                zHas = false;
            } else {
                Locale locale = Locale.ENGLISH;
                zHas = new JSONObject(string.toLowerCase(locale)).has(str.toLowerCase(locale));
            }
            if (zHas) {
                return true;
            }
        }
        return false;
    }

    public final boolean d(String str) {
        f fVar;
        boolean z;
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        new b(context);
        if (z) {
            sharedPreferences = fVar;
        }
        if (sharedPreferences.getBoolean("OT_GPP_IS_ENABLED", false)) {
            com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
            String string = dVar.b().getString("OT_TEMPLATE_TYPE", "");
            String str2 = com.onetrust.otpublishers.headless.Internal.a.j(string) ? "" : string;
            if (dVar.b().getBoolean("OT_USE_GPP_USNATIONAL", false)) {
                str2 = "USNATIONAL";
            }
            if (str.equalsIgnoreCase(str2)) {
                return false;
            }
        }
        return true;
    }
}
