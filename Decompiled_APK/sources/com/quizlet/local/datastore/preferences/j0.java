package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class j0 extends kotlin.coroutines.jvm.internal.c {
    public androidx.datastore.preferences.core.f j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.interactor.course.a l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j0(com.quizlet.data.interactor.course.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.k(this);
    }
}
