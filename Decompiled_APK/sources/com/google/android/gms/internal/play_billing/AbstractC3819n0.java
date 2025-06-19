package com.google.android.gms.internal.play_billing;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import com.android.billingclient.api.Purchase;
import com.comscore.android.ConnectivityType;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.play_billing.n0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3819n0 {
    public static final int a = Runtime.getRuntime().availableProcessors();

    public static int a(Bundle bundle, String str) {
        if (bundle == null) {
            f(str, "Unexpected null bundle received!");
            return 6;
        }
        Object obj = bundle.get("RESPONSE_CODE");
        if (obj == null) {
            e(str, "getResponseCodeFromBundle() got null response code, assuming OK");
            return 0;
        }
        if (obj instanceof Integer) {
            return ((Integer) obj).intValue();
        }
        f(str, "Unexpected type for bundle response code: ".concat(obj.getClass().getName()));
        return 6;
    }

    public static void b(Bundle bundle, String str, long j) {
        bundle.putString("playBillingLibraryVersion", str);
        bundle.putLong("billingClientSessionId", j);
    }

    public static com.android.billingclient.api.e c(String str, Intent intent) {
        if (intent != null) {
            com.android.billingclient.api.d dVarA = com.android.billingclient.api.e.a();
            dVarA.b = a(intent.getExtras(), str);
            dVarA.c = d(intent.getExtras(), str);
            return dVarA.a();
        }
        f("BillingHelper", "Got null intent!");
        com.android.billingclient.api.d dVarA2 = com.android.billingclient.api.e.a();
        dVarA2.b = 6;
        dVarA2.c = "An internal error occurred.";
        return dVarA2.a();
    }

    public static String d(Bundle bundle, String str) {
        if (bundle == null) {
            f(str, "Unexpected null bundle received!");
            return "";
        }
        Object obj = bundle.get("DEBUG_MESSAGE");
        if (obj == null) {
            e(str, "getDebugMessageFromBundle() got null response code, assuming OK");
            return "";
        }
        if (obj instanceof String) {
            return (String) obj;
        }
        f(str, "Unexpected type for debug message: ".concat(obj.getClass().getName()));
        return "";
    }

    public static void e(String str, String str2) {
        if (!Log.isLoggable(str, 2) || str2.isEmpty()) {
            return;
        }
        int i = ConnectivityType.UNKNOWN;
        while (!str2.isEmpty() && i > 0) {
            int iMin = Math.min(str2.length(), Math.min(4000, i));
            str2.substring(0, iMin);
            str2 = str2.substring(iMin);
            i -= iMin;
        }
    }

    public static void f(String str, String str2) {
        if (Log.isLoggable(str, 5)) {
            Log.w(str, str2);
        }
    }

    public static void g(String str, String str2, Throwable th) {
        try {
            if (Log.isLoggable(str, 5)) {
                if (th == null) {
                    Log.w(str, str2);
                } else {
                    Log.w(str, str2, th);
                }
            }
        } catch (Throwable unused) {
        }
    }

    public static Bundle h(com.android.billingclient.api.e eVar, int i) {
        Bundle bundle = new Bundle();
        bundle.putInt("RESPONSE_CODE", eVar.a);
        bundle.putString("DEBUG_MESSAGE", eVar.b);
        bundle.putInt("LOG_REASON", i - 1);
        return bundle;
    }

    public static Purchase i(String str, String str2) {
        if (str == null || str2 == null) {
            e("BillingHelper", "Received a null purchase data.");
            return null;
        }
        try {
            return new Purchase(str, str2);
        } catch (JSONException e) {
            f("BillingHelper", "Got JSONException while parsing purchase data: ".concat(e.toString()));
            return null;
        }
    }
}
