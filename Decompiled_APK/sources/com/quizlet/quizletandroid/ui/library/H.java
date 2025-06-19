package com.quizlet.quizletandroid.ui.library;

import com.quizlet.data.model.EnumC4164s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new H(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c0 c0Var = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            com.quizlet.quizletandroid.interactor.p pVar = c0Var.k;
            this.j = 1;
            obj = pVar.b(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        EnumC4164s0 enumC4164s0 = (EnumC4164s0) obj;
        s0 s0Var = c0Var.t;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value, null, enumC4164s0, null, null, null, false, false, false, 253)));
        return Unit.a;
    }
}
