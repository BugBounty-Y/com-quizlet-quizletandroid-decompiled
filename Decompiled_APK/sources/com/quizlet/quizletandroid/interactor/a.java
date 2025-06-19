package com.quizlet.quizletandroid.interactor;

import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBUser;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public DBUser k;
    public DBGroup l;
    public long m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.quizlet.data.repository.folderwithcreatorinclass.e o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.folderwithcreatorinclass.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.f(null, null, this, false);
    }
}
