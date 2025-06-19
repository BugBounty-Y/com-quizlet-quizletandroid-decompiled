package coil3.network;

import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;

/* loaded from: classes.dex */
public final class f implements e {
    public final ConnectivityManager b;

    public f(ConnectivityManager connectivityManager) {
        this.b = connectivityManager;
    }

    @Override // coil3.network.e
    public final boolean a() {
        ConnectivityManager connectivityManager = this.b;
        NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(connectivityManager.getActiveNetwork());
        return networkCapabilities != null && networkCapabilities.hasCapability(12);
    }
}
