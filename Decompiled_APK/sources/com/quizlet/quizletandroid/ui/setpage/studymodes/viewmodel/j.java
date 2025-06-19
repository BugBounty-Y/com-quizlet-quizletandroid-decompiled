package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import java.util.List;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public s j;
    public List k;
    public long l;
    public /* synthetic */ Object m;
    public final /* synthetic */ s n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(s sVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.g(0L, null, this);
    }
}
