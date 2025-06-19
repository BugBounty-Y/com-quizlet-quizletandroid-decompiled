package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class K4 {
    public static T4 j;
    public static final com.google.android.gms.internal.mlkit_vision_barcode.G k;
    public final String a;
    public final String b;
    public final J4 c;
    public final com.google.mlkit.common.sdkinternal.i d;
    public final com.google.android.gms.tasks.m e;
    public final com.google.android.gms.tasks.m f;
    public final String g;
    public final int h;
    public final HashMap i = new HashMap();

    static {
        Object[] objArr = {"optional-module-barcode", "com.google.android.gms.vision.barcode"};
        objArr[0].getClass();
        objArr[1].getClass();
        k = new com.google.android.gms.internal.mlkit_vision_barcode.G(objArr, 1);
    }

    public K4(Context context, com.google.mlkit.common.sdkinternal.i iVar, J4 j4) {
        new HashMap();
        this.a = context.getPackageName();
        this.b = com.google.mlkit.common.sdkinternal.c.a(context);
        this.d = iVar;
        this.c = j4;
        O4.b();
        this.g = "vision-common";
        com.google.mlkit.common.sdkinternal.e eVarA = com.google.mlkit.common.sdkinternal.e.a();
        androidx.camera.core.impl.utils.executor.c cVar = new androidx.camera.core.impl.utils.executor.c(this, 11);
        eVarA.getClass();
        this.e = com.google.mlkit.common.sdkinternal.e.b(cVar);
        com.google.mlkit.common.sdkinternal.e eVarA2 = com.google.mlkit.common.sdkinternal.e.a();
        iVar.getClass();
        com.google.android.gms.internal.mlkit_common.p pVar = new com.google.android.gms.internal.mlkit_common.p(iVar, 3);
        eVarA2.getClass();
        this.f = com.google.mlkit.common.sdkinternal.e.b(pVar);
        com.google.android.gms.internal.mlkit_vision_barcode.G g = k;
        this.h = g.containsKey("vision-common") ? com.google.android.gms.dynamite.c.d(context, (String) g.get("vision-common"), false) : -1;
    }
}
