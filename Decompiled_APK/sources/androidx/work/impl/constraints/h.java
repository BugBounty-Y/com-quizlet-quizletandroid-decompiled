package androidx.work.impl.constraints;

import android.net.ConnectivityManager;
import androidx.work.C1425f;
import androidx.work.impl.model.q;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class h implements androidx.work.impl.constraints.controllers.e {
    public final ConnectivityManager a;

    public h(ConnectivityManager connManager) {
        Intrinsics.checkNotNullParameter(connManager, "connManager");
        this.a = connManager;
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final C4986c a(C1425f constraints) {
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        return e0.g(new g(constraints, this, null));
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final boolean b(q workSpec) {
        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
        return workSpec.j.b.a != null;
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final boolean c(q workSpec) {
        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
        if (b(workSpec)) {
            throw new IllegalStateException("isCurrentlyConstrained() must never be called onNetworkRequestConstraintController. isCurrentlyConstrained() is called only on older platforms where NetworkRequest isn't supported");
        }
        return false;
    }
}
