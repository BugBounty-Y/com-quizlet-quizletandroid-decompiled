package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public /* synthetic */ Object k;
    public final /* synthetic */ J l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(J j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(this);
    }
}
