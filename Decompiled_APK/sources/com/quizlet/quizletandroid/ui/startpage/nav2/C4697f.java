package com.quizlet.quizletandroid.ui.startpage.nav2;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4697f extends kotlin.coroutines.jvm.internal.c {
    public androidx.work.impl.model.e j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.work.impl.model.e l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4697f(androidx.work.impl.model.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.o(this);
    }
}
