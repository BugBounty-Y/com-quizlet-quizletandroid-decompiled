package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4733b extends kotlin.coroutines.jvm.internal.c {
    public C4739h j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C4739h l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4733b(C4739h c4739h, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c4739h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return C4739h.A(this.l, null, this);
    }
}
