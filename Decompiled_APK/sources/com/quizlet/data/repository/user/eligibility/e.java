package com.quizlet.data.repository.user.eligibility;

import java.util.Set;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public g j;
    public Set k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ g n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.e(null, false, this);
    }
}
