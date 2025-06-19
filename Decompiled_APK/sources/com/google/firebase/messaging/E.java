package com.google.firebase.messaging;

import android.os.Binder;
import android.os.Process;
import android.util.Log;

/* loaded from: classes2.dex */
public final class E extends Binder {
    public final com.airbnb.lottie.network.c a;

    public E(com.airbnb.lottie.network.c cVar) {
        this.a = cVar;
    }

    public final void a(F f) {
        if (Binder.getCallingUid() != Process.myUid()) {
            throw new SecurityException("Binding only allowed within app");
        }
        Log.isLoggable("FirebaseMessaging", 3);
        AbstractServiceC3969f.access$000((AbstractServiceC3969f) this.a.b, f.a).b(new androidx.arch.core.executor.a(1), new com.google.android.material.search.a(f, 12));
    }
}
