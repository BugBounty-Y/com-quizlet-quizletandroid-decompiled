package com.quizlet.quizletandroid.initializers.app;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.u;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ u k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r4v5, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            ?? r4 = ((com.quizlet.usecase.a) this.k.V0.get()).a;
            e eVar = new e();
            this.j = 1;
            if (r4.b(eVar, this) == aVar) {
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
