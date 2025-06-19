package com.quizlet.remote.model.search;

import com.quizlet.quizletandroid.ui.login.h;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public /* synthetic */ Object k;
    public final /* synthetic */ h l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.g(null, this);
    }
}
