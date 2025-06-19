package com.quizlet.features.setpage.terms.viewmodel;

import androidx.activity.compose.p;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.C5013v;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            c cVar = this.k;
            Object objI = e0.i(new C5013v(cVar.e.k(cVar.i), new p(cVar, (h) null, 2)), new androidx.compose.runtime.internal.c(2, cVar, c.class, "onDiagramUpdated", "onDiagramUpdated(Lcom/quizlet/studiablemodels/diagrams/DiagramData;)V", 4, 6), this);
            if (objI != obj2) {
                objI = Unit.a;
            }
            if (objI == obj2) {
                return obj2;
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
