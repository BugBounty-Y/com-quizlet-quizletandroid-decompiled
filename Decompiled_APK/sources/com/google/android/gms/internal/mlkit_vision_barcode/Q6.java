package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.ComponentCallbacks2;
import android.content.Context;

/* loaded from: classes2.dex */
public abstract class Q6 {
    public static final /* synthetic */ int a = 0;

    public static final androidx.datastore.preferences.core.b a() {
        return new androidx.datastore.preferences.core.b(true);
    }

    public static Object b(Context context) {
        ComponentCallbacks2 componentCallbacks2B = N6.b(context.getApplicationContext());
        boolean z = componentCallbacks2B instanceof dagger.hilt.internal.b;
        Class<?> cls = componentCallbacks2B.getClass();
        if (z) {
            return ((dagger.hilt.internal.b) componentCallbacks2B).d();
        }
        throw new IllegalArgumentException(androidx.compose.ui.node.B.d(cls, "Hilt BroadcastReceiver must be attached to an @HiltAndroidApp Application. Found: "));
    }
}
