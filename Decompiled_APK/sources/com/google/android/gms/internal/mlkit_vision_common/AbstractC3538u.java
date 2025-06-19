package com.google.android.gms.internal.mlkit_vision_common;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3538u {
    public static final /* synthetic */ int a = 0;

    public static final void a(Object obj, String message) {
        Intrinsics.checkNotNullParameter(obj, "<this>");
        Intrinsics.checkNotNullParameter(message, "message");
        c(obj);
        com.amazon.aps.ads.c.a();
    }

    public static final void b(Object obj, String message) {
        Intrinsics.checkNotNullParameter(obj, "<this>");
        Intrinsics.checkNotNullParameter(message, "message");
        c(obj);
        com.amazon.aps.ads.c.a();
    }

    public static final String c(Object obj) {
        Intrinsics.checkNotNullParameter(obj, "<this>");
        String simpleName = obj.getClass().getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "this::class.java.simpleName");
        return simpleName;
    }
}
