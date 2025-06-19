package com.quizlet.local.datastore.preferences;

/* renamed from: com.quizlet.local.datastore.preferences.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4570f extends kotlin.coroutines.jvm.internal.c {
    public androidx.datastore.preferences.core.f j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C4574j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4570f(C4574j c4574j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c4574j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(0L, this);
    }
}
