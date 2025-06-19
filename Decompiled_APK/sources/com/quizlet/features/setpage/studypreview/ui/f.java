package com.quizlet.features.setpage.studypreview.ui;

import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.foundation.pager.y;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.snapshots.q;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.S;
import androidx.compose.ui.n;
import androidx.navigation.serialization.k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_common.A;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements kotlin.jvm.functions.d {
    public final /* synthetic */ C0466e a;
    public final /* synthetic */ float b;
    public final /* synthetic */ float c;
    public final /* synthetic */ q d;
    public final /* synthetic */ kotlinx.collections.immutable.e e;
    public final /* synthetic */ com.quizlet.features.setpage.studypreview.g f;

    public f(C0466e c0466e, float f, float f2, q qVar, kotlinx.collections.immutable.e eVar, com.quizlet.features.setpage.studypreview.g gVar) {
        this.a = c0466e;
        this.b = f;
        this.c = f2;
        this.d = qVar;
        this.e = eVar;
        this.f = gVar;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        y HorizontalPager = (y) obj;
        int iIntValue = ((Number) obj2).intValue();
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj3;
        int iIntValue2 = ((Number) obj4).intValue();
        Intrinsics.checkNotNullParameter(HorizontalPager, "$this$HorizontalPager");
        final float fAbs = 1.0f - Math.abs(this.a.c.j() + (r10.j() - iIntValue));
        if (fAbs < 0.93f) {
            fAbs = 0.93f;
        }
        androidx.compose.ui.q qVarD = K0.d(K0.o(n.b, this.b), this.c);
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1027008688);
        boolean zC = c0814p.c(fAbs);
        Object objI = c0814p.I();
        Object obj5 = C0804k.a;
        if (zC || objI == obj5) {
            objI = new Function1() { // from class: com.quizlet.features.setpage.studypreview.ui.e
                @Override // kotlin.jvm.functions.Function1
                public final Object invoke(Object obj6) {
                    S graphicsLayer = (S) obj6;
                    Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                    graphicsLayer.o(fAbs);
                    return Unit.a;
                }
            };
            c0814p.i0(objI);
        }
        c0814p.p(false);
        androidx.compose.ui.q qVarP = F.p(qVarD, (Function1) objI);
        q qVar = this.d;
        com.quizlet.assembly.compose.components.flashcards.b bVar = (com.quizlet.assembly.compose.components.flashcards.b) qVar.get(iIntValue);
        kotlinx.collections.immutable.e eVar = this.e;
        com.quizlet.features.setpage.studypreview.data.a aVar = (com.quizlet.features.setpage.studypreview.data.a) eVar.get(iIntValue);
        c0814p.X(-1027001944);
        boolean zF = c0814p.f(qVar);
        boolean z = (((iIntValue2 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.d(iIntValue)) || (iIntValue2 & 48) == 32;
        Object obj6 = this.f;
        boolean zH = z | zF | c0814p.h(obj6) | c0814p.h(eVar);
        Object objI2 = c0814p.I();
        if (zH || objI2 == obj5) {
            objI2 = new k(iIntValue, 3, qVar, obj6, eVar);
            c0814p.i0(objI2);
        }
        Function1 function1 = (Function1) objI2;
        c0814p.p(false);
        c0814p.X(-1026995288);
        boolean zH2 = c0814p.h(obj6);
        Object objI3 = c0814p.I();
        if (zH2 || objI3 == obj5) {
            objI3 = new com.quizlet.featuregate.growthbook.a(obj6, 13);
            c0814p.i0(objI3);
        }
        c0814p.p(false);
        A.c(bVar, aVar, qVarP, function1, (Function0) objI3, c0814p, 0);
        return Unit.a;
    }
}
