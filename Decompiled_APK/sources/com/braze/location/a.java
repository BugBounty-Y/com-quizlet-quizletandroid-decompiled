package com.braze.location;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public a() {
        try {
            Intrinsics.e(Class.forName("com.braze.location.BrazeInternalGeofenceApi").getDeclaredConstructor(null).newInstance(null), "null cannot be cast to non-null type com.braze.location.IBrazeGeofenceApi");
            throw new ClassCastException();
        } catch (Exception unused) {
        }
    }
}
