package com.google.android.gms.internal.mlkit_vision_document_scanner;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.k4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3657k4 {
    public static final /* synthetic */ int a = 0;

    public static final String a(String key, JSONObject jSONObject) {
        Intrinsics.checkNotNullParameter(jSONObject, "<this>");
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            return jSONObject.getString(key);
        } catch (Exception unused) {
            return null;
        }
    }

    public static final String b(JSONObject jSONObject, String key, String defaultValue) throws JSONException {
        String string;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(defaultValue, "defaultValue");
        if (jSONObject != null) {
            try {
                string = jSONObject.getString(key);
            } catch (Exception unused) {
                string = defaultValue;
            }
        } else {
            string = null;
        }
        return string == null ? defaultValue : string;
    }

    public static final boolean c(String key, JSONObject jSONObject) {
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            return jSONObject.getBoolean(key);
        } catch (Exception unused) {
            return false;
        }
    }
}
