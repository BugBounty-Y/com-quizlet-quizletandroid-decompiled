package com.google.firebase.remoteconfig;

import com.google.android.gms.common.api.internal.InterfaceC1644b;
import java.util.Iterator;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class e implements InterfaceC1644b {
    public static final AtomicReference a = new AtomicReference();

    @Override // com.google.android.gms.common.api.internal.InterfaceC1644b
    public final void a(boolean z) {
        Random random = f.j;
        synchronized (f.class) {
            Iterator it2 = f.k.values().iterator();
            while (it2.hasNext()) {
                ((b) it2.next()).c(z);
            }
        }
    }
}
