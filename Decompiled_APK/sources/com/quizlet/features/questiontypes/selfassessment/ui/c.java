package com.quizlet.features.questiontypes.selfassessment.ui;

import androidx.compose.foundation.gestures.k1;
import androidx.compose.ui.input.pointer.B;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.studiablemodels.StudiableImage;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Function1 l;
    public final /* synthetic */ StudiableImage m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(Function1 function1, StudiableImage studiableImage, h hVar) {
        super(2, hVar);
        this.l = function1;
        this.m = studiableImage;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.l, this.m, hVar);
        cVar.k = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((B) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            B b = (B) this.k;
            b bVar = new b(this.l, this.m, 0);
            this.j = 1;
            if (k1.d(b, bVar, null, this, 13) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
