package com.quizlet.features.notes.detail.viewmodels;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public v j;
    public v k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ v n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(v vVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.D(false, this);
    }
}
