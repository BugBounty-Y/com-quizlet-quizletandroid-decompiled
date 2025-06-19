package com.quizlet.features.achievements.ui.composables;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function1 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(kotlin.coroutines.h hVar, Function0 function0, Function1 function1) {
        super(2, hVar);
        this.k = function0;
        this.l = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(hVar, this.k, this.l);
        d.j = obj;
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((com.quizlet.features.achievements.navigation.a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (!Intrinsics.b((com.quizlet.features.achievements.navigation.a) this.j, com.quizlet.features.achievements.navigation.a.a)) {
            throw new NoWhenBranchMatchedException();
        }
        this.k.invoke();
        return Unit.a;
    }
}
