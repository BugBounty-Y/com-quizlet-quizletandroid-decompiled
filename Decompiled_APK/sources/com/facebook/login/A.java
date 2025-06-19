package com.facebook.login;

import android.content.Context;
import android.os.Bundle;
import java.util.ArrayList;
import java.util.concurrent.ScheduledExecutorService;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class A {
    public static final A a = new A();
    public static v b;

    public static final com.quizlet.data.repository.folderset.c a(JSONObject jSONObject) throws JSONException {
        String strOptString;
        JSONArray jSONArray = jSONObject.getJSONObject("permissions").getJSONArray("data");
        ArrayList grantedPermissions = new ArrayList();
        ArrayList declinedPermissions = new ArrayList();
        ArrayList expiredPermissions = new ArrayList();
        int length = jSONArray.length();
        for (int i = 0; i < length; i++) {
            JSONObject jSONObjectOptJSONObject = jSONArray.optJSONObject(i);
            String permission = jSONObjectOptJSONObject.optString("permission");
            Intrinsics.checkNotNullExpressionValue(permission, "permission");
            if (permission.length() != 0 && !permission.equals("installed") && (strOptString = jSONObjectOptJSONObject.optString("status")) != null) {
                int iHashCode = strOptString.hashCode();
                if (iHashCode != -1309235419) {
                    if (iHashCode != 280295099) {
                        if (iHashCode == 568196142 && strOptString.equals("declined")) {
                            declinedPermissions.add(permission);
                        }
                    } else if (strOptString.equals("granted")) {
                        grantedPermissions.add(permission);
                    }
                } else if (strOptString.equals("expired")) {
                    expiredPermissions.add(permission);
                }
            }
        }
        Intrinsics.checkNotNullParameter(grantedPermissions, "grantedPermissions");
        Intrinsics.checkNotNullParameter(declinedPermissions, "declinedPermissions");
        Intrinsics.checkNotNullParameter(expiredPermissions, "expiredPermissions");
        com.quizlet.data.repository.folderset.c cVar = new com.quizlet.data.repository.folderset.c(5, false);
        cVar.b = grantedPermissions;
        cVar.c = declinedPermissions;
        cVar.d = expiredPermissions;
        return cVar;
    }

    public static final Bundle b(String str) {
        ScheduledExecutorService scheduledExecutorService = v.d;
        Bundle bundle = new Bundle();
        bundle.putLong("1_timestamp_ms", System.currentTimeMillis());
        bundle.putString("0_auth_logger_id", str);
        bundle.putString("3_method", "");
        bundle.putString("2_result", "");
        bundle.putString("5_error_message", "");
        bundle.putString("4_error_code", "");
        bundle.putString("6_extras", "");
        return bundle;
    }

    public synchronized v c(Context context) {
        if (context == null) {
            try {
                context = com.facebook.o.a();
            } catch (Throwable th) {
                throw th;
            }
        }
        if (b == null) {
            b = new v(context, com.facebook.o.b());
        }
        return b;
    }
}
