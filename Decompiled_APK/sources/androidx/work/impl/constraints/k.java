package androidx.work.impl.constraints;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import androidx.work.z;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k extends ConnectivityManager.NetworkCallback {
    public static final k a = new k();
    public static final Object b = new Object();
    public static final LinkedHashMap c = new LinkedHashMap();

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
        List<Map.Entry> listW0;
        Intrinsics.checkNotNullParameter(network, "network");
        Intrinsics.checkNotNullParameter(networkCapabilities, "networkCapabilities");
        z zVarC = z.c();
        int i = o.a;
        zVarC.getClass();
        synchronized (b) {
            listW0 = CollectionsKt.w0(c.entrySet());
        }
        for (Map.Entry entry : listW0) {
            ((Function1) entry.getValue()).invoke(((NetworkRequest) entry.getKey()).canBeSatisfiedBy(networkCapabilities) ? a.a : new b(7));
        }
    }

    @Override // android.net.ConnectivityManager.NetworkCallback
    public final void onLost(Network network) {
        List listW0;
        Intrinsics.checkNotNullParameter(network, "network");
        z zVarC = z.c();
        int i = o.a;
        zVarC.getClass();
        synchronized (b) {
            listW0 = CollectionsKt.w0(c.values());
        }
        Iterator it2 = listW0.iterator();
        while (it2.hasNext()) {
            ((Function1) it2.next()).invoke(new b(7));
        }
    }
}
