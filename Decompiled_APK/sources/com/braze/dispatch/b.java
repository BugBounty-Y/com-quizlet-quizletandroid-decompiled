package com.braze.dispatch;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends ConnectivityManager.NetworkCallback {
    public final /* synthetic */ f a;

    public b(f fVar) {
        this.a = fVar;
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
        Intrinsics.checkNotNullParameter(network, "network");
        Intrinsics.checkNotNullParameter(networkCapabilities, "networkCapabilities");
        super.onCapabilitiesChanged(network, networkCapabilities);
        this.a.a(networkCapabilities);
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onLost(Network network) {
        Intrinsics.checkNotNullParameter(network, "network");
        super.onLost(network);
        Network activeNetwork = this.a.i.getActiveNetwork();
        f fVar = this.a;
        fVar.a(fVar.i.getNetworkCapabilities(activeNetwork));
    }
}
