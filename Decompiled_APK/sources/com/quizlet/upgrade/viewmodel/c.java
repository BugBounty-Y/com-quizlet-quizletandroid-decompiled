package com.quizlet.upgrade.viewmodel;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.quizletandroid.ui.activitycenter.models.a j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ h m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.C(null, this);
    }
}
