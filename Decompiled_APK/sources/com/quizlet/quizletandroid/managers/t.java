package com.quizlet.quizletandroid.managers;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.N;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ u k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                C4885d c4885dX = new N(io.reactivex.rxjava3.core.i.n(com.quizlet.billing.manager.f.l), new com.quizlet.billing.subscriptions.f(this.k.f, 3), true).x(20);
                this.j = 1;
                if (I1.b(c4885dX, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
        } catch (Throwable th) {
            timber.log.c.a.p(th);
        }
        return Unit.a;
    }
}
