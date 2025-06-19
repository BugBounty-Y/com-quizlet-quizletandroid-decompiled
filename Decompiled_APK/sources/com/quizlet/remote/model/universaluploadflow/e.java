package com.quizlet.remote.model.universaluploadflow;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public String j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.remote.model.notes.e l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.quizlet.remote.model.notes.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return com.quizlet.remote.model.notes.e.g(this.l, null, null, this);
    }
}
