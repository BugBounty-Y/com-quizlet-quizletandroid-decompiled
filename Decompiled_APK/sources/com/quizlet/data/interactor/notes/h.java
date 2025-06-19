package com.quizlet.data.interactor.notes;

import com.quizlet.shared.models.notes.FullStudyNotesInfo;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.login.a j;
    public String k;
    public FullStudyNotesInfo l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.quizlet.data.repository.login.a n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(com.quizlet.data.repository.login.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.i(null, this, false);
    }
}
