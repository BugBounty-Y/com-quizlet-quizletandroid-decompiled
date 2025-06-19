package com.quizlet.data.interactor.set.permissions;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.user.a k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.quizlet.data.repository.user.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.r(0L, this);
    }
}
