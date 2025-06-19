package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ TestModeStartFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(TestModeStartFragment testModeStartFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = testModeStartFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = TestModeStartFragment.l;
            TestModeStartFragment testModeStartFragment = this.k;
            d0 d0Var = testModeStartFragment.U().i;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, testModeStartFragment, TestModeStartFragment.class, "onNavigationEvent", "onNavigationEvent(Lcom/quizlet/quizletandroid/ui/studymodes/testmode/start/NavigationEvent;)V", 4, 17);
            this.j = 1;
            if (e0.i(d0Var, cVar, this) == aVar) {
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
