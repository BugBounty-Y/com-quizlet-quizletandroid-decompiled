package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class e0 extends kotlin.coroutines.jvm.internal.c {
    public androidx.datastore.preferences.core.f j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.google.mlkit.vision.documentscanner.internal.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e0(com.google.mlkit.vision.documentscanner.internal.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.l(0L, this);
    }
}
