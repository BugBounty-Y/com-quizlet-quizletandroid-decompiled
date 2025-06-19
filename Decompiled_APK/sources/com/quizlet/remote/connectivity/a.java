package com.quizlet.remote.connectivity;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import io.reactivex.rxjava3.subjects.d;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends ConnectivityManager.NetworkCallback {
    public final d a;
    public final LinkedHashMap b;

    public a() {
        d dVar = new d(new com.quizlet.data.connectivity.b(true, false, false));
        Intrinsics.checkNotNullExpressionValue(dVar, "createDefault(...)");
        this.a = dVar;
        this.b = new LinkedHashMap();
    }

    public final void a(boolean z) {
        LinkedHashMap linkedHashMap = this.b;
        boolean z2 = !linkedHashMap.isEmpty();
        LinkedHashMap linkedHashMap2 = new LinkedHashMap();
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            if (((NetworkCapabilities) entry.getValue()).hasTransport(1)) {
                linkedHashMap2.put(entry.getKey(), entry.getValue());
            }
        }
        this.a.b(new com.quizlet.data.connectivity.b(z2, !linkedHashMap2.isEmpty(), z));
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
        Intrinsics.checkNotNullParameter(network, "network");
        Intrinsics.checkNotNullParameter(networkCapabilities, "networkCapabilities");
        LinkedHashMap linkedHashMap = this.b;
        boolean z = !linkedHashMap.isEmpty();
        if (networkCapabilities.hasCapability(12)) {
            linkedHashMap.put(network, networkCapabilities);
        }
        a(z);
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onLost(Network network) {
        Intrinsics.checkNotNullParameter(network, "network");
        LinkedHashMap linkedHashMap = this.b;
        boolean z = !linkedHashMap.isEmpty();
        linkedHashMap.remove(network);
        a(z);
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onUnavailable() {
        a(false);
    }
}
