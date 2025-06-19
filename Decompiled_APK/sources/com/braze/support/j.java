package com.braze.support;

import com.braze.models.BrazeGeofence;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class j {
    public static final j a = new j();

    public static final ArrayList a(JSONArray geofenceJson) {
        Intrinsics.checkNotNullParameter(geofenceJson, "geofenceJson");
        ArrayList arrayList = new ArrayList();
        int length = geofenceJson.length();
        for (int i = 0; i < length; i++) {
            JSONObject jSONObjectOptJSONObject = geofenceJson.optJSONObject(i);
            if (jSONObjectOptJSONObject == null) {
                try {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(19), 6, (Object) null);
                    Unit unit = Unit.a;
                } catch (JSONException e) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new com.braze.communication.dust.j(jSONObjectOptJSONObject, 15), 4, (Object) null);
                    Unit unit2 = Unit.a;
                } catch (Exception e2) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.E, (Throwable) e2, false, (Function0) new com.braze.communication.dust.j(jSONObjectOptJSONObject, 14), 4, (Object) null);
                    Unit unit3 = Unit.a;
                }
            } else {
                arrayList.add(new BrazeGeofence(jSONObjectOptJSONObject));
            }
        }
        return arrayList;
    }

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Failed to deserialize geofence Json:", jSONObject);
    }

    public static final String a() {
        return "Received null or blank geofence Json. Not parsing.";
    }

    public static final String a(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Failed to deserialize geofence Json due to JSONException: ", jSONObject);
    }
}
