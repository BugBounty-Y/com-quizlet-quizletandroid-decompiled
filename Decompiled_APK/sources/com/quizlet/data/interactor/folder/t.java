package com.quizlet.data.interactor.folder;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4119d0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.explanations.myexplanations.a l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(com.quizlet.data.repository.explanations.myexplanations.a aVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = aVar;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t tVar = new t(this.l, this.m, hVar);
        tVar.k = obj;
        return tVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                com.quizlet.data.repository.explanations.myexplanations.a aVar2 = this.l;
                long j = this.m;
                kotlin.p pVar = kotlin.r.b;
                com.quizlet.data.repository.folder.i iVar = (com.quizlet.data.repository.folder.i) aVar2.b;
                this.j = 1;
                obj = iVar.g(j, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            objB = (AbstractC4119d0) obj;
            kotlin.p pVar2 = kotlin.r.b;
        } catch (Throwable th) {
            kotlin.p pVar3 = kotlin.r.b;
            objB = Z.b(th);
        }
        return new kotlin.r(objB);
    }
}
