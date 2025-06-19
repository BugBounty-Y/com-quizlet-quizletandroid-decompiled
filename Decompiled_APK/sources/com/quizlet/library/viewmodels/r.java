package com.quizlet.library.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ s j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        s0 s0Var = this.j.e;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, n.a));
        return Unit.a;
    }
}
