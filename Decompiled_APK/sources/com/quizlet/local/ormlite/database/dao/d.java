package com.quizlet.local.ormlite.database.dao;

import com.quizlet.data.interactor.achievements.f;
import java.util.List;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public f j;
    public List k;
    public /* synthetic */ Object l;
    public final /* synthetic */ f m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.o(null, this);
    }
}
