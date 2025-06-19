package com.quizlet.login.common.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function1 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.k, hVar);
        mVar.j = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((com.quizlet.login.magiclink.data.a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.login.magiclink.data.a aVar2 = (com.quizlet.login.magiclink.data.a) this.j;
        if (aVar2 instanceof com.quizlet.login.magiclink.data.a) {
            this.k.invoke(aVar2.a);
        }
        return Unit.a;
    }
}
