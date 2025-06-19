package com.google.android.gms.internal.mlkit_common;

import android.content.Context;
import java.util.HashMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class q {
    public static final l b = l.a(1, new Object[]{"optional-module-barcode", "com.google.android.gms.vision.barcode"}, null);
    public final String a;

    public q(Context context, com.google.mlkit.common.sdkinternal.i iVar) {
        new HashMap();
        new HashMap();
        context.getPackageName();
        com.google.mlkit.common.sdkinternal.c.a(context);
        synchronized (u.class) {
            if (u.b == null) {
                u.b = new u(0);
            }
        }
        this.a = "common";
        com.google.mlkit.common.sdkinternal.e eVarA = com.google.mlkit.common.sdkinternal.e.a();
        androidx.camera.core.impl.utils.executor.c cVar = new androidx.camera.core.impl.utils.executor.c(this, 9);
        eVarA.getClass();
        com.google.mlkit.common.sdkinternal.e.b(cVar);
        com.google.mlkit.common.sdkinternal.e eVarA2 = com.google.mlkit.common.sdkinternal.e.a();
        Objects.requireNonNull(iVar);
        p pVar = new p(iVar, 0);
        eVarA2.getClass();
        com.google.mlkit.common.sdkinternal.e.b(pVar);
        l lVar = b;
        if (lVar.containsKey("common")) {
            com.google.android.gms.dynamite.c.d(context, (String) lVar.get("common"), false);
        }
    }
}
