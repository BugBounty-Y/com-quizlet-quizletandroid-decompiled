package com.onetrust.otpublishers.headless.Internal.Preferences;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import org.json.JSONArray;
import org.json.JSONException;

/* loaded from: classes2.dex */
public class d {
    public final SharedPreferences a;
    public final f b;
    public final boolean c;
    public final Context d;

    public d(Context context, String str) {
        this.d = context;
        this.a = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat(str), 0);
    }

    public final void a() {
        if (this.c) {
            try {
                com.onetrust.otpublishers.headless.Internal.profile.c cVar = new com.onetrust.otpublishers.headless.Internal.profile.c(this.d);
                String string = cVar.a.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                    JSONArray jSONArray = new JSONArray(string);
                    for (int i = 0; i < jSONArray.length(); i++) {
                        cVar.i(jSONArray.getString(i));
                    }
                }
            } catch (JSONException e) {
                Z.p("Error on clearing multi-profile files. Error = ", e, "OneTrust", 6);
            }
        }
        this.a.edit().clear().apply();
    }

    public final SharedPreferences b() {
        return this.c ? this.b : this.a;
    }

    public final boolean c() {
        SharedPreferences sharedPreferencesB = b();
        String string = sharedPreferencesB.getString("OTT_CREATE_CONSENT_PROFILE_STRING", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return false;
        }
        boolean z = Boolean.parseBoolean(string);
        int i = sharedPreferencesB.getInt("OTT_DATA_SUBJECT_IDENTIFIER_TYPE", 1);
        if (z && i == 1) {
            return false;
        }
        return z;
    }

    public d(@NonNull Context context) {
        this.d = context;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        this.a = sharedPreferences;
        if (Q.a(context)) {
            this.c = true;
            this.b = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
        }
    }
}
