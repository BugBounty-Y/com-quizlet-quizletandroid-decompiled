package androidx.paging;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5027k0;

/* loaded from: classes.dex */
public final class O {
    public final C1336q0 a;
    public final T0 b;
    public final C5027k0 c;

    public O(C1336q0 snapshot, T0 t0, C5027k0 job) {
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        Intrinsics.checkNotNullParameter(job, "job");
        this.a = snapshot;
        this.b = t0;
        this.c = job;
    }
}
