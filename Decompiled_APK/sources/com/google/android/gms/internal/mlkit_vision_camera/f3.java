package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class f3 {
    public static com.google.common.collect.x i;
    public static final com.google.common.collect.C j = com.google.common.collect.C.d(1, new Object[]{"optional-module-barcode", "com.google.android.gms.vision.barcode"}, null);
    public final String a;
    public final String b;
    public final c3 c;
    public final com.google.mlkit.common.sdkinternal.i d;
    public final com.google.android.gms.tasks.m e;
    public final com.google.android.gms.tasks.m f;
    public final String g;
    public final int h;

    public f3(Context context, com.google.mlkit.common.sdkinternal.i iVar, c3 c3Var) {
        new HashMap();
        new HashMap();
        this.a = context.getPackageName();
        this.b = com.google.mlkit.common.sdkinternal.c.a(context);
        this.d = iVar;
        this.c = c3Var;
        this.g = "camera";
        com.google.mlkit.common.sdkinternal.e eVarA = com.google.mlkit.common.sdkinternal.e.a();
        d3 d3Var = new d3();
        eVarA.getClass();
        this.e = com.google.mlkit.common.sdkinternal.e.b(d3Var);
        com.google.mlkit.common.sdkinternal.e eVarA2 = com.google.mlkit.common.sdkinternal.e.a();
        iVar.getClass();
        com.google.android.gms.internal.mlkit_common.p pVar = new com.google.android.gms.internal.mlkit_common.p(iVar, 2);
        eVarA2.getClass();
        this.f = com.google.mlkit.common.sdkinternal.e.b(pVar);
        com.google.common.collect.C c = j;
        this.h = c.containsKey("camera") ? com.google.android.gms.dynamite.c.d(context, (String) c.get("camera"), false) : -1;
    }
}
