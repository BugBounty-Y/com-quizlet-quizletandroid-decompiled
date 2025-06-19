package com.google.firebase.sessions;

import android.app.Application;
import android.content.Context;
import android.util.Log;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3994p {
    public final com.google.firebase.h a;
    public final com.google.firebase.sessions.settings.j b;

    public C3994p(com.google.firebase.h firebaseApp, com.google.firebase.sessions.settings.j settings, CoroutineContext backgroundDispatcher, d0 lifecycleServiceBinder) {
        Intrinsics.checkNotNullParameter(firebaseApp, "firebaseApp");
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        Intrinsics.checkNotNullParameter(lifecycleServiceBinder, "lifecycleServiceBinder");
        this.a = firebaseApp;
        this.b = settings;
        firebaseApp.a();
        Context applicationContext = firebaseApp.a.getApplicationContext();
        if (applicationContext instanceof Application) {
            ((Application) applicationContext).registerActivityLifecycleCallbacks(e0.a);
            kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(backgroundDispatcher), null, null, new C3993o(this, backgroundDispatcher, lifecycleServiceBinder, null), 3);
        } else {
            Log.e(FirebaseSessionsRegistrar.TAG, "Failed to register lifecycle callbacks, unexpected context " + applicationContext.getClass() + '.');
        }
    }
}
