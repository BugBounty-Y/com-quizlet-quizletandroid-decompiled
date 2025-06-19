package com.quizlet.upgrade.data;

/* renamed from: com.quizlet.upgrade.data.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4839g extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.user.a k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4839g(com.quizlet.data.repository.user.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.q(false, null, this);
    }
}
