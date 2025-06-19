package com.google.android.gms.internal.mlkit_vision_common;

import java.util.ArrayList;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class B2 {
    public static final /* synthetic */ int a = 0;

    public static com.facebook.appevents.codeless.internal.c a(JSONObject mapping) throws JSONException {
        Intrinsics.checkNotNullParameter(mapping, "mapping");
        String eventName = mapping.getString("event_name");
        String string = mapping.getString("method");
        Intrinsics.checkNotNullExpressionValue(string, "mapping.getString(\"method\")");
        Locale ENGLISH = Locale.ENGLISH;
        Intrinsics.checkNotNullExpressionValue(ENGLISH, "ENGLISH");
        String upperCase = string.toUpperCase(ENGLISH);
        Intrinsics.checkNotNullExpressionValue(upperCase, "this as java.lang.String).toUpperCase(locale)");
        com.facebook.appevents.codeless.internal.b bVarValueOf = com.facebook.appevents.codeless.internal.b.valueOf(upperCase);
        String string2 = mapping.getString("event_type");
        Intrinsics.checkNotNullExpressionValue(string2, "mapping.getString(\"event_type\")");
        Intrinsics.checkNotNullExpressionValue(ENGLISH, "ENGLISH");
        String upperCase2 = string2.toUpperCase(ENGLISH);
        Intrinsics.checkNotNullExpressionValue(upperCase2, "this as java.lang.String).toUpperCase(locale)");
        com.facebook.appevents.codeless.internal.a aVarValueOf = com.facebook.appevents.codeless.internal.a.valueOf(upperCase2);
        String appVersion = mapping.getString("app_version");
        JSONArray jSONArray = mapping.getJSONArray("path");
        ArrayList arrayList = new ArrayList();
        int length = jSONArray.length();
        for (int i = 0; i < length; i++) {
            JSONObject jsonPath = jSONArray.getJSONObject(i);
            Intrinsics.checkNotNullExpressionValue(jsonPath, "jsonPath");
            arrayList.add(new com.facebook.appevents.codeless.internal.e(jsonPath));
        }
        String pathType = mapping.optString("path_type", "absolute");
        JSONArray jSONArrayOptJSONArray = mapping.optJSONArray("parameters");
        ArrayList arrayList2 = new ArrayList();
        if (jSONArrayOptJSONArray != null) {
            int length2 = jSONArrayOptJSONArray.length();
            for (int i2 = 0; i2 < length2; i2++) {
                JSONObject jsonParameter = jSONArrayOptJSONArray.getJSONObject(i2);
                Intrinsics.checkNotNullExpressionValue(jsonParameter, "jsonParameter");
                arrayList2.add(new com.facebook.appevents.codeless.internal.d(jsonParameter));
            }
        }
        String componentId = mapping.optString("component_id");
        String activityName = mapping.optString("activity_name");
        Intrinsics.checkNotNullExpressionValue(eventName, "eventName");
        Intrinsics.checkNotNullExpressionValue(appVersion, "appVersion");
        Intrinsics.checkNotNullExpressionValue(componentId, "componentId");
        Intrinsics.checkNotNullExpressionValue(pathType, "pathType");
        Intrinsics.checkNotNullExpressionValue(activityName, "activityName");
        return new com.facebook.appevents.codeless.internal.c(eventName, bVarValueOf, aVarValueOf, appVersion, arrayList, arrayList2, componentId, pathType, activityName);
    }
}
