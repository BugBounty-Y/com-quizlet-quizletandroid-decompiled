package com.quizlet.data.repository.studysetwithcreatorinclass;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public g j;
    public g k;
    public /* synthetic */ Object l;
    public final /* synthetic */ g m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.j(0L, this);
    }
}
