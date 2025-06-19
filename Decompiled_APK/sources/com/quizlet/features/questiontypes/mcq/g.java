package com.quizlet.features.questiontypes.mcq;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        l lVar = this.k;
        if (i == 0) {
            Z.e(obj);
            if (lVar.l) {
                long j = lVar.h.c ? 600L : 1200L;
                this.j = 1;
                if (E.n(j, this) == aVar) {
                    return aVar;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        E.A(p0.j(lVar), null, null, new h(lVar, null), 3);
        return Unit.a;
    }
}
