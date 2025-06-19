package com.quizlet.data.interactor.folder;

/* loaded from: classes2.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.explanations.myexplanations.a k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(com.quizlet.data.repository.explanations.myexplanations.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objH = this.k.h(0L, this);
        return objH == kotlin.coroutines.intrinsics.a.a ? objH : new kotlin.r(objH);
    }
}
