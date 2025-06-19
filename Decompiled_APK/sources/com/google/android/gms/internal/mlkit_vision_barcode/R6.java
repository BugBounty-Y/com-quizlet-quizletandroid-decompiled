package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class R6 {
    public static final /* synthetic */ int a = 0;

    public static final androidx.datastore.preferences.core.f a(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return new androidx.datastore.preferences.core.f(name);
    }

    public static void b(boolean z, String str, Object... objArr) {
        if (!z) {
            throw new IllegalStateException(String.format(str, objArr));
        }
    }

    public static final androidx.datastore.preferences.core.f c(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return new androidx.datastore.preferences.core.f(name);
    }

    public static final androidx.datastore.preferences.core.f d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return new androidx.datastore.preferences.core.f(name);
    }
}
