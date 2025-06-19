package com.quizlet.features.flashcards;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;
    public final /* synthetic */ com.quizlet.features.flashcards.autoplay.o l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ androidx.lifecycle.J n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(Context context, androidx.lifecycle.J j, S s, com.quizlet.features.flashcards.autoplay.o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
        this.l = oVar;
        this.m = context;
        this.n = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.m, this.n, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            S s = this.k;
            s0 s0Var = s.u;
            C4243q c4243q = new C4243q(this.m, this.n, s, this.l, null);
            this.j = 1;
            if (e0.i(s0Var, c4243q, this) == aVar) {
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
