package com.appsflyer.internal;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.appsflyer.AFLogger;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.collections.C4931w;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.sequences.Sequence;
import kotlin.sequences.q;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFi1qSDK extends AFi1pSDK {

    @Metadata
    /* renamed from: com.appsflyer.internal.AFi1qSDK$1, reason: invalid class name */
    public static final class AnonymousClass1 extends r implements Function1<Network, NetworkInfo> {
        public AnonymousClass1() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        /* renamed from: x_, reason: merged with bridge method [inline-methods] */
        public final NetworkInfo invoke(Network network) {
            ConnectivityManager connectivityManager = AFi1qSDK.this.getMonetizationNetwork;
            Intrinsics.d(connectivityManager);
            return connectivityManager.getNetworkInfo(network);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AFi1qSDK(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "");
    }

    private static boolean w_(NetworkCapabilities networkCapabilities) {
        return (networkCapabilities == null || !networkCapabilities.hasTransport(4) || networkCapabilities.hasCapability(15)) ? false : true;
    }

    @Override // com.appsflyer.internal.AFi1pSDK
    public final boolean getMonetizationNetwork() {
        Network[] allNetworks;
        try {
            ConnectivityManager connectivityManager = this.getMonetizationNetwork;
            if (connectivityManager == null || (allNetworks = connectivityManager.getAllNetworks()) == null) {
                return false;
            }
            ArrayList arrayList = new ArrayList();
            for (Network network : allNetworks) {
                ConnectivityManager connectivityManager2 = this.getMonetizationNetwork;
                Intrinsics.d(connectivityManager2);
                NetworkCapabilities networkCapabilities = connectivityManager2.getNetworkCapabilities(network);
                if (networkCapabilities != null) {
                    arrayList.add(networkCapabilities);
                }
            }
            if (arrayList.isEmpty()) {
                return false;
            }
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                if (w_((NetworkCapabilities) it2.next())) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            AFLogger.afErrorLog("Failed collecting ivc data", e);
            return false;
        }
    }

    @Override // com.appsflyer.internal.AFi1pSDK
    @NotNull
    public final String getRevenue() {
        Network[] allNetworks;
        Object next;
        ConnectivityManager connectivityManager = this.getMonetizationNetwork;
        if (connectivityManager == null || (allNetworks = connectivityManager.getAllNetworks()) == null) {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        Intrinsics.checkNotNullParameter(allNetworks, "<this>");
        Sequence c4931w = allNetworks.length == 0 ? kotlin.sequences.d.a : new C4931w(allNetworks, 0);
        if (c4931w == null) {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        kotlin.sequences.e eVar = new kotlin.sequences.e(q.i(c4931w, new AnonymousClass1()));
        while (true) {
            if (!eVar.hasNext()) {
                next = null;
                break;
            }
            next = eVar.next();
            if (AFi1pSDK.v_((NetworkInfo) next)) {
                break;
            }
        }
        NetworkInfo networkInfo = (NetworkInfo) next;
        if (networkInfo == null) {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        int type = networkInfo.getType();
        return type != 0 ? type != 1 ? DtbDeviceDataRetriever.ORIENTATION_UNKNOWN : "WIFI" : "MOBILE";
    }
}
