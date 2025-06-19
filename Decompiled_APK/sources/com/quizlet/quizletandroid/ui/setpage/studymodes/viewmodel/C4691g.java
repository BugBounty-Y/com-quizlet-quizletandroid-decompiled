package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

/* renamed from: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4691g extends kotlin.coroutines.jvm.internal.c {
    public s j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ s m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4691g(s sVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.f(0L, this);
    }
}
