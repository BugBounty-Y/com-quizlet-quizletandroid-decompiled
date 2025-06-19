package com.braze.support;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import com.braze.AbstractC1476b;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();

    public static final String a(String str) {
        return AbstractC1476b.a("Unexpected system broadcast received [", str, ']');
    }

    public static final com.braze.enums.f a(Intent intent, ConnectivityManager connectivityManager) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        Intrinsics.checkNotNullParameter(connectivityManager, "connectivityManager");
        String action = intent.getAction();
        if (!"android.net.conn.CONNECTIVITY_CHANGE".equals(action)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(action, 6), 6, (Object) null);
            return com.braze.enums.f.a;
        }
        try {
            NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            boolean booleanExtra = intent.getBooleanExtra("noConnectivity", false);
            if (activeNetworkInfo == null || booleanExtra) {
                return com.braze.enums.f.a;
            }
            int type = activeNetworkInfo.getType();
            if (type != 0) {
                return (type == 1 || type == 6) ? com.braze.enums.f.d : type != 9 ? com.braze.enums.f.a : com.braze.enums.f.c;
            }
            int subtype = activeNetworkInfo.getSubtype();
            return subtype != 3 ? (subtype == 13 || subtype == 20) ? com.braze.enums.f.d : com.braze.enums.f.b : com.braze.enums.f.c;
        } catch (SecurityException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new v(14), 4, (Object) null);
            return com.braze.enums.f.a;
        }
    }

    public static final String a() {
        return "Failed to get active network information. Ensure the permission android.permission.ACCESS_NETWORK_STATE is defined in your AndroidManifest.xml";
    }

    public static final com.braze.enums.f a(NetworkCapabilities networkCapabilities) {
        if (networkCapabilities == null) {
            return com.braze.enums.f.a;
        }
        int iMin = Math.min(networkCapabilities.getLinkDownstreamBandwidthKbps(), networkCapabilities.getLinkUpstreamBandwidthKbps());
        if (iMin > 14000) {
            return com.braze.enums.f.d;
        }
        if (iMin > 4000) {
            return com.braze.enums.f.c;
        }
        return com.braze.enums.f.b;
    }
}
