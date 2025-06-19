package com.quizlet.features.folders.composables;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.P4;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class M implements kotlin.jvm.functions.c {
    public final /* synthetic */ com.quizlet.ui.models.content.listitem.o a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ int c;
    public final /* synthetic */ androidx.compose.foundation.lazy.A d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ InterfaceC0773a0 g;
    public final /* synthetic */ Function2 h;

    public M(com.quizlet.ui.models.content.listitem.o oVar, Function1 function1, int i, androidx.compose.foundation.lazy.A a, boolean z, boolean z2, InterfaceC0773a0 interfaceC0773a0, Function2 function2) {
        this.a = oVar;
        this.b = function1;
        this.c = i;
        this.d = a;
        this.e = z;
        this.f = z2;
        this.g = interfaceC0773a0;
        this.h = function2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        androidx.compose.animation.F AnimatedVisibility = (androidx.compose.animation.F) obj;
        ((Number) obj3).intValue();
        Intrinsics.checkNotNullParameter(AnimatedVisibility, "$this$AnimatedVisibility");
        com.quizlet.ui.models.content.listitem.o oVar = this.a;
        String strD = P4.d(oVar);
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        c0814p.X(-567684796);
        Function1 function1 = this.b;
        boolean zF = c0814p.f(function1) | c0814p.h(oVar);
        int i = this.c;
        boolean zD = zF | c0814p.d(i);
        Object objI = c0814p.I();
        if (zD || objI == C0804k.a) {
            objI = new K(function1, oVar, i, 0);
            c0814p.i0(objI);
        }
        c0814p.p(false);
        P5.a(strD, (Function0) objI, new com.quizlet.ui.compose.util.a(true, this.d, null, 4), androidx.compose.runtime.internal.e.e(20616605, new L(this.e, this.b, this.a, this.f, this.g, this.h), c0814p), c0814p, 3072);
        return Unit.a;
    }
}
