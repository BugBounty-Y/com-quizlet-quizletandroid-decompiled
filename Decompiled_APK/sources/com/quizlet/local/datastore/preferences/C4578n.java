package com.quizlet.local.datastore.preferences;

/* renamed from: com.quizlet.local.datastore.preferences.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4578n extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C4579o l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4578n(C4579o c4579o, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c4579o;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
