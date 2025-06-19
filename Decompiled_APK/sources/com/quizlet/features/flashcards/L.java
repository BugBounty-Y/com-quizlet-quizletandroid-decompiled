package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;
    public final /* synthetic */ com.quizlet.features.flashcards.data.m l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(S s, com.quizlet.features.flashcards.data.m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
        this.l = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        S s = this.k;
        if (i == 0) {
            Z.e(obj);
            s.t.l(com.quizlet.features.flashcards.data.o.a(s.G(), 0, 0, 0, 0, false, false, false, false, this.l, null, 767));
            this.j = 1;
            if (kotlinx.coroutines.E.n(3000L, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        s.H();
        return Unit.a;
    }
}
