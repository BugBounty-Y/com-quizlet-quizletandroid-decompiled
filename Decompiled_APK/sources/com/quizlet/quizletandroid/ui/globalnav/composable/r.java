package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.compose.material3.O3;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O3 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(O3 o3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        r rVar = new r(this.l, hVar);
        rVar.k = obj;
        return rVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((com.quizlet.features.infra.snackbar.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.snackbar.composables.a aVar2 = new com.quizlet.features.infra.snackbar.composables.a((com.quizlet.features.infra.snackbar.l) this.k);
            this.j = 1;
            if (this.l.a(aVar2, this) == aVar) {
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
