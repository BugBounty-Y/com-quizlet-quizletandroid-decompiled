package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import java.util.Iterator;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public i j;
    public Iterator k;
    public long l;
    public /* synthetic */ Object m;
    public final /* synthetic */ i n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return i.B(this.n, null, 0L, this);
    }
}
