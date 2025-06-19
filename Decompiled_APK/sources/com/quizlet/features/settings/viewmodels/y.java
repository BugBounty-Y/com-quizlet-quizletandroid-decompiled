package com.quizlet.features.settings.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ I j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new y(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        I i = this.j;
        com.quizlet.features.settings.data.models.c cVar = new com.quizlet.features.settings.data.models.c(i.e.a.getBoolean("PREF_OFFLINE_TOGGLE", true));
        while (true) {
            s0 s0Var = i.n;
            Object value = s0Var.getValue();
            I i2 = i;
            if (s0Var.k(value, com.quizlet.features.settings.data.states.y.a((com.quizlet.features.settings.data.states.y) value, null, null, false, false, null, null, cVar, null, false, false, null, false, 8127))) {
                return Unit.a;
            }
            i = i2;
        }
    }
}
