package com.google.android.gms.internal.measurement;

import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final /* synthetic */ class Z implements Callable {
    @Override // java.util.concurrent.Callable
    public final Object call() {
        C3010j2 c3010j2 = new C3010j2("internal.platform", 4);
        c3010j2.b.put("getVersion", new C3010j2("getVersion", 3));
        return c3010j2;
    }
}
