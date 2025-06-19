package androidx.work.impl.constraints.trackers;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class h {
    public static final String a;

    static {
        String strE = z.e("NetworkStateTracker");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"NetworkStateTracker\")");
        a = strE;
    }

    public static final androidx.work.impl.constraints.i a(ConnectivityManager connectivityManager) {
        boolean zHasCapability;
        NetworkCapabilities networkCapabilities;
        Intrinsics.checkNotNullParameter(connectivityManager, "<this>");
        NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
        boolean z = activeNetworkInfo != null && activeNetworkInfo.isConnected();
        Intrinsics.checkNotNullParameter(connectivityManager, "<this>");
        try {
            Intrinsics.checkNotNullParameter(connectivityManager, "<this>");
            Network activeNetwork = connectivityManager.getActiveNetwork();
            Intrinsics.checkNotNullParameter(connectivityManager, "<this>");
            networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork);
        } catch (SecurityException e) {
            z.c().b(a, "Unable to validate active network", e);
        }
        if (networkCapabilities != null) {
            Intrinsics.checkNotNullParameter(networkCapabilities, "<this>");
            zHasCapability = networkCapabilities.hasCapability(16);
        } else {
            zHasCapability = false;
        }
        return new androidx.work.impl.constraints.i(z, zHasCapability, connectivityManager.isActiveNetworkMetered(), (activeNetworkInfo == null || activeNetworkInfo.isRoaming()) ? false : true);
    }
}
