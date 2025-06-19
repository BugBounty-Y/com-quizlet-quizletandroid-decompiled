package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ ActivityCenterModalFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(ActivityCenterModalFragment activityCenterModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = activityCenterModalFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            ActivityCenterModalFragment activityCenterModalFragment = this.k;
            d0 d0Var = ((com.quizlet.features.infra.snackbar.viewmodel.c) ((com.quizlet.features.infra.snackbar.viewmodel.a) activityCenterModalFragment.I.getValue())).b;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, activityCenterModalFragment, ActivityCenterModalFragment.class, "showSnackbar", "showSnackbar(Lcom/quizlet/features/infra/snackbar/ShowSnackbarData;)V", 4, 12);
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
