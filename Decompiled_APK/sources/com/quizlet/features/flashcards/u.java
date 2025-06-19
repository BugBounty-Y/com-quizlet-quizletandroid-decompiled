package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function1 l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ Function2 n;
    public final /* synthetic */ Function2 o;
    public final /* synthetic */ Function1 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(Function0 function0, Function1 function1, Function1 function12, Function2 function2, Function2 function22, Function1 function13, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function1;
        this.m = function12;
        this.n = function2;
        this.o = function22;
        this.p = function13;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        u uVar = new u(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
        uVar.j = obj;
        return uVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((com.quizlet.features.flashcards.data.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.flashcards.data.l lVar = (com.quizlet.features.flashcards.data.l) this.j;
        if (lVar instanceof com.quizlet.features.flashcards.data.f) {
            this.k.invoke();
        } else if (lVar instanceof com.quizlet.features.flashcards.data.g) {
            this.l.invoke(lVar);
        } else if (lVar instanceof com.quizlet.features.flashcards.data.h) {
            this.m.invoke(lVar);
        } else if (lVar instanceof com.quizlet.features.flashcards.data.i) {
            com.quizlet.features.flashcards.data.i iVar = (com.quizlet.features.flashcards.data.i) lVar;
            this.n.invoke(iVar.a, iVar.b);
        } else if (lVar instanceof com.quizlet.features.flashcards.data.j) {
            com.quizlet.features.flashcards.data.j jVar = (com.quizlet.features.flashcards.data.j) lVar;
            this.o.invoke(new Long(jVar.a), jVar.b);
        } else {
            if (!(lVar instanceof com.quizlet.features.flashcards.data.k)) {
                throw new NoWhenBranchMatchedException();
            }
            this.p.invoke(lVar);
        }
        return Unit.a;
    }
}
