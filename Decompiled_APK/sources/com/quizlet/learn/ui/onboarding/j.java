package com.quizlet.learn.ui.onboarding;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.learn.data.onboarding.A;
import com.quizlet.learn.data.onboarding.B;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ x k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.k, hVar);
        jVar.j = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        boolean z = ((B) this.j) instanceof A;
        x xVar = this.k;
        if (z) {
            x.d(xVar);
        } else {
            xVar.a();
        }
        return Unit.a;
    }
}
