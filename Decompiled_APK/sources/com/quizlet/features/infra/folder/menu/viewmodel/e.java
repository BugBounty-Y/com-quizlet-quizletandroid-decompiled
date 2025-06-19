package com.quizlet.features.infra.folder.menu.viewmodel;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public m j;
    public String k;
    public com.quizlet.data.interactor.folderstudymaterial.g l;
    public /* synthetic */ Object m;
    public final /* synthetic */ m n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return m.a(this.n, null, null, this);
    }
}
