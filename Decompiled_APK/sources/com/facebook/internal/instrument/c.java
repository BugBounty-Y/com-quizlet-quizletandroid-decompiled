package com.facebook.internal.instrument;

import android.os.Build;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c {
    public String a;
    public a b;
    public JSONArray c;
    public String d;
    public String e;
    public String f;
    public Long g;

    public final boolean a() {
        a aVar = this.b;
        int i = aVar == null ? -1 : b.a[aVar.ordinal()];
        Long l = this.g;
        if (i == 1) {
            return (this.c == null || l == null) ? false : true;
        }
        String str = this.f;
        return i != 2 ? ((i != 3 && i != 4 && i != 5) || str == null || l == null) ? false : true : (str == null || this.e == null || l == null) ? false : true;
    }

    public final void b() {
        if (a()) {
            G2.i(this.a, toString());
        }
    }

    public final String toString() throws JSONException {
        a aVar = this.b;
        int i = aVar == null ? -1 : b.a[aVar.ordinal()];
        Long l = this.g;
        JSONObject jSONObject = null;
        try {
            if (i == 1) {
                JSONObject jSONObject2 = new JSONObject();
                JSONArray jSONArray = this.c;
                if (jSONArray != null) {
                    jSONObject2.put("feature_names", jSONArray);
                }
                if (l != null) {
                    jSONObject2.put("timestamp", l);
                }
                jSONObject = jSONObject2;
            } else if (i == 2 || i == 3 || i == 4 || i == 5) {
                JSONObject jSONObject3 = new JSONObject();
                jSONObject3.put("device_os_version", Build.VERSION.RELEASE);
                jSONObject3.put("device_model", Build.MODEL);
                String str = this.d;
                if (str != null) {
                    jSONObject3.put("app_version", str);
                }
                if (l != null) {
                    jSONObject3.put("timestamp", l);
                }
                String str2 = this.e;
                if (str2 != null) {
                    jSONObject3.put("reason", str2);
                }
                String str3 = this.f;
                if (str3 != null) {
                    jSONObject3.put("callstack", str3);
                }
                if (aVar != null) {
                    jSONObject3.put(DBUserFields.Names.USER_UPGRADE_TYPE, aVar);
                }
                jSONObject = jSONObject3;
            }
        } catch (JSONException unused) {
        }
        if (jSONObject == null) {
            String string = new JSONObject().toString();
            Intrinsics.checkNotNullExpressionValue(string, "JSONObject().toString()");
            return string;
        }
        String string2 = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string2, "params.toString()");
        return string2;
    }
}
