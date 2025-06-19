package androidx.work.impl.constraints.trackers;

import android.content.Context;
import android.net.ConnectivityManager;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g extends e {
    public final ConnectivityManager f;
    public final androidx.work.impl.constraints.d g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(Context context, androidx.work.impl.utils.taskexecutor.c taskExecutor) {
        super(context, taskExecutor);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(taskExecutor, "taskExecutor");
        Object systemService = ((Context) this.b).getSystemService("connectivity");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.net.ConnectivityManager");
        this.f = (ConnectivityManager) systemService;
        this.g = new androidx.work.impl.constraints.d(this, 1);
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final Object c() {
        return h.a(this.f);
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final void e() {
        try {
            z zVarC = z.c();
            String str = h.a;
            zVarC.getClass();
            ConnectivityManager connectivityManager = this.f;
            androidx.work.impl.constraints.d networkCallback = this.g;
            Intrinsics.checkNotNullParameter(connectivityManager, "<this>");
            Intrinsics.checkNotNullParameter(networkCallback, "networkCallback");
            connectivityManager.registerDefaultNetworkCallback(networkCallback);
        } catch (IllegalArgumentException e) {
            z.c().b(h.a, "Received exception while registering network callback", e);
        } catch (SecurityException e2) {
            z.c().b(h.a, "Received exception while registering network callback", e2);
        }
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final void f() {
        try {
            z zVarC = z.c();
            String str = h.a;
            zVarC.getClass();
            ConnectivityManager connectivityManager = this.f;
            androidx.work.impl.constraints.d networkCallback = this.g;
            Intrinsics.checkNotNullParameter(connectivityManager, "<this>");
            Intrinsics.checkNotNullParameter(networkCallback, "networkCallback");
            connectivityManager.unregisterNetworkCallback(networkCallback);
        } catch (IllegalArgumentException e) {
            z.c().b(h.a, "Received exception while unregistering network callback", e);
        } catch (SecurityException e2) {
            z.c().b(h.a, "Received exception while unregistering network callback", e2);
        }
    }
}
