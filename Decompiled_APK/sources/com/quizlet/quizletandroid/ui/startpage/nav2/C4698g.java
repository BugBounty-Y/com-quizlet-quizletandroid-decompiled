package com.quizlet.quizletandroid.ui.startpage.nav2;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4698g extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.work.impl.model.e k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4698g(androidx.work.impl.model.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.q(this);
    }
}
