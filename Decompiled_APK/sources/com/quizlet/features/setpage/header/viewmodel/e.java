package com.quizlet.features.setpage.header.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, long j, h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            d0 d0Var = this.k.h;
            com.quizlet.features.setpage.header.data.c cVar = new com.quizlet.features.setpage.header.data.c(this.l);
            this.j = 1;
            if (d0Var.emit(cVar, this) == aVar) {
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
