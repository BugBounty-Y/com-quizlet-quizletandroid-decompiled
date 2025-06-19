package com.google.android.gms.ads.internal.overlay;

import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final class i implements Callable {
    public final long a;

    public i(long j) {
        this.a = j;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        if (AdOverlayInfoParcel.z.remove(Long.valueOf(this.a)) == null) {
            return null;
        }
        com.google.android.gms.ads.internal.j.C.h.h("AdOverlayObjectsCleanupTask", new Exception("Key was non-null in AdOverlayObjectsCleanupTask"));
        return null;
    }
}
