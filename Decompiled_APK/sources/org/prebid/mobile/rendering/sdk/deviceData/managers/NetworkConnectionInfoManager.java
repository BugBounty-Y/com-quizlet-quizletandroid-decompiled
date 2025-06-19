package org.prebid.mobile.rendering.sdk.deviceData.managers;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import org.prebid.mobile.rendering.networking.parameters.UserParameters$ConnectionType;
import org.prebid.mobile.rendering.sdk.BaseManager;

/* loaded from: classes3.dex */
public final class NetworkConnectionInfoManager extends BaseManager {
    public final ConnectivityManager b;

    public NetworkConnectionInfoManager(Context context) {
        super(context);
        if (a() != null) {
            this.b = (ConnectivityManager) a().getApplicationContext().getSystemService("connectivity");
        }
    }

    public final UserParameters$ConnectionType b() {
        UserParameters$ConnectionType userParameters$ConnectionType = UserParameters$ConnectionType.a;
        if (a() == null) {
            return userParameters$ConnectionType;
        }
        ConnectivityManager connectivityManager = this.b;
        NetworkInfo activeNetworkInfo = (connectivityManager == null || a().checkCallingOrSelfPermission("android.permission.ACCESS_NETWORK_STATE") != 0) ? null : connectivityManager.getActiveNetworkInfo();
        if (activeNetworkInfo == null) {
            return userParameters$ConnectionType;
        }
        int type = activeNetworkInfo.getType();
        return activeNetworkInfo.isConnected() ? (type == 0 || type == 4 || type == 5 || type == 2 || type == 3) ? UserParameters$ConnectionType.c : UserParameters$ConnectionType.b : userParameters$ConnectionType;
    }
}
