package com.onetrust.otpublishers.headless.gpp;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;
    public final Context b;
    public final b c;

    public c(@NonNull Context context) {
        this.b = context;
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        this.c = new b(context);
    }

    public static String a(int i, String str, ArrayList arrayList) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return "";
        }
        arrayList.add(Integer.valueOf(i));
        return str;
    }

    public static String b(String str, String str2) {
        return !com.onetrust.otpublishers.headless.Internal.a.j(str) ? android.support.v4.media.session.a.l(str2, "~", str) : str2;
    }

    public static void d(String str, int i, boolean z, StringBuilder sb) {
        if (str.equals(String.valueOf(i)) && z) {
            if (com.onetrust.otpublishers.headless.Internal.a.j(sb.toString())) {
                sb.append(str);
            } else {
                sb.append("_");
                sb.append(str);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0132  */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 3 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c() {
        /*
            Method dump skipped, instructions count: 941
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.gpp.c.c():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:66:0x0118  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String e(java.util.ArrayList r21) {
        /*
            Method dump skipped, instructions count: 561
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.gpp.c.e(java.util.ArrayList):java.lang.String");
    }

    public final JSONObject f() {
        String string = this.a.b().getString("OT_GPP_DATA_BACKUP", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                W.a("getGppBackUpData: ", e, "GPPStringHandler", 6);
            }
        }
        return new JSONObject();
    }

    public final boolean g() {
        Context context = this.b;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            new com.onetrust.otpublishers.headless.Internal.Preferences.c(sharedPreferences, context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", "")), 0));
        }
        String string = defaultSharedPreferences.getString(OTGppKeys.IAB_GPP_USP1_STRING, "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            string = defaultSharedPreferences.getString(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING, "");
        }
        String str = com.onetrust.otpublishers.headless.Internal.a.j(string) ? "" : string;
        return (com.onetrust.otpublishers.headless.Internal.a.j(str) || str.equals("1---")) ? false : true;
    }
}
