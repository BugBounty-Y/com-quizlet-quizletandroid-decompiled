package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.google.android.gms.common.internal.C1658h;
import java.util.HashMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class p7 {
    public static C3604e i;
    public static final com.google.android.gms.internal.mlkit_vision_barcode.G j;
    public final String a;
    public final String b;
    public final o7 c;
    public final com.google.mlkit.common.sdkinternal.i d;
    public final com.google.android.gms.tasks.m e;
    public final com.google.android.gms.tasks.m f;
    public final String g;
    public final int h;

    static {
        Object[] objArr = {"optional-module-barcode", "com.google.android.gms.vision.barcode"};
        Objects.requireNonNull(objArr[0]);
        Objects.requireNonNull(objArr[1]);
        j = new com.google.android.gms.internal.mlkit_vision_barcode.G(objArr, 2);
    }

    public p7(Context context, com.google.mlkit.common.sdkinternal.i iVar, o7 o7Var) {
        new HashMap();
        new HashMap();
        this.a = context.getPackageName();
        this.b = com.google.mlkit.common.sdkinternal.c.a(context);
        this.d = iVar;
        this.c = o7Var;
        s7.b();
        this.g = "play-services-mlkit-document-scanner";
        com.google.mlkit.common.sdkinternal.e eVarA = com.google.mlkit.common.sdkinternal.e.a();
        androidx.camera.core.impl.utils.executor.c cVar = new androidx.camera.core.impl.utils.executor.c(this, 12);
        eVarA.getClass();
        this.e = com.google.mlkit.common.sdkinternal.e.b(cVar);
        com.google.mlkit.common.sdkinternal.e eVarA2 = com.google.mlkit.common.sdkinternal.e.a();
        Objects.requireNonNull(iVar);
        com.google.android.gms.internal.mlkit_common.p pVar = new com.google.android.gms.internal.mlkit_common.p(iVar, 4);
        eVarA2.getClass();
        this.f = com.google.mlkit.common.sdkinternal.e.b(pVar);
        com.google.android.gms.internal.mlkit_vision_barcode.G g = j;
        this.h = g.containsKey("play-services-mlkit-document-scanner") ? com.google.android.gms.dynamite.c.d(context, (String) g.get("play-services-mlkit-document-scanner"), false) : -1;
    }

    public final void a(com.quizlet.data.repository.widget.b bVar, EnumC3610e5 enumC3610e5) {
        com.google.android.gms.tasks.m mVar = this.e;
        com.google.mlkit.common.sdkinternal.k.a.execute(new RunnableC0069f(13, this, bVar, enumC3610e5, mVar.l() ? (String) mVar.h() : C1658h.c.a(this.g), false));
    }
}
