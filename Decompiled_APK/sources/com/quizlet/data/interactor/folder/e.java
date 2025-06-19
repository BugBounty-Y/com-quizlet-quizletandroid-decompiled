package com.quizlet.data.interactor.folder;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ f k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objB = this.k.b(0L, this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new kotlin.r(objB);
    }
}
