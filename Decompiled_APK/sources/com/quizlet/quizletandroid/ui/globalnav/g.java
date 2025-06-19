package com.quizlet.quizletandroid.ui.globalnav;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ GlobalNavigationActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(GlobalNavigationActivity globalNavigationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = globalNavigationActivity;
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
        if (i == 0) {
            Z.e(obj);
            GlobalNavigationActivity globalNavigationActivity = this.k;
            J0 j0 = ((com.quizlet.login.magiclink.viewmodel.g) globalNavigationActivity.t.getValue()).f;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, globalNavigationActivity, GlobalNavigationActivity.class, "goToIntroWithMagicLink", "goToIntroWithMagicLink(Ljava/lang/String;)V", 4, 14);
            this.j = 1;
            if (e0.i(j0, cVar, this) == aVar) {
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
