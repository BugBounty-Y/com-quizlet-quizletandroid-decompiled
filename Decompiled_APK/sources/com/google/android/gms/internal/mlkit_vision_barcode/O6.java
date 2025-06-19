package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class O6 {
    public static Thread a;

    public static androidx.datastore.b a(String name, com.airbnb.lottie.network.c cVar, int i) {
        if ((i & 2) != 0) {
            cVar = null;
        }
        androidx.datastore.preferences.a produceMigrations = androidx.datastore.preferences.a.a;
        kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
        kotlinx.coroutines.internal.d scope = kotlinx.coroutines.E.c(kotlinx.coroutines.scheduling.d.b.plus(kotlinx.coroutines.E.e()));
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(produceMigrations, "produceMigrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        return new androidx.datastore.b(name, cVar, produceMigrations, scope);
    }
}
