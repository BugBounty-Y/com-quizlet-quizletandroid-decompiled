package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new z(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        P p = this.k;
        if (i == 0) {
            Z.e(obj);
            androidx.compose.runtime.internal.j jVar = p.K;
            long jD = p.D();
            this.j = 1;
            obj = jVar.r(jD, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        List list = (List) obj;
        s0 s0Var = p.M1;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.setpage.screenstates.t(list)));
        return Unit.a;
    }
}
