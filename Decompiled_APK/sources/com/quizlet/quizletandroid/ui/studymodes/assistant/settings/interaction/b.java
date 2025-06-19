package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction;

import com.quizlet.quizletandroid.ui.setcreation.managers.n;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public boolean j;
    public /* synthetic */ Object k;
    public final /* synthetic */ n l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(n nVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.f(null, this);
    }
}
