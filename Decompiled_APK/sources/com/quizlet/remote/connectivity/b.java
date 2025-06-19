package com.quizlet.remote.connectivity;

import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import io.reactivex.rxjava3.internal.util.d;
import io.reactivex.rxjava3.internal.util.e;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.data.connectivity.a {
    public final a a;

    public b(ConnectivityManager connectivityManager, a networkCallback, NetworkRequest networkRequest) {
        Intrinsics.checkNotNullParameter(connectivityManager, "connectivityManager");
        Intrinsics.checkNotNullParameter(networkCallback, "networkCallback");
        Intrinsics.checkNotNullParameter(networkRequest, "networkRequest");
        this.a = networkCallback;
        if (connectivityManager.getActiveNetwork() == null) {
            networkCallback.a(false);
        }
        connectivityManager.registerNetworkCallback(networkRequest, networkCallback);
    }

    public final com.quizlet.data.connectivity.b a() {
        Object obj = this.a.a.a.get();
        if (e.a(obj) || (obj instanceof d)) {
            obj = null;
        }
        if (obj != null) {
            return (com.quizlet.data.connectivity.b) obj;
        }
        throw new IllegalArgumentException("Required value was null.");
    }
}
