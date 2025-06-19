package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public com.google.android.material.floatingactionbutton.c j;
    public long k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.google.android.material.floatingactionbutton.c n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(com.google.android.material.floatingactionbutton.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.n = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.l(0L, false, this);
    }
}
