package io.ktor.client.engine.okhttp;

import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public f j;
    public CoroutineContext k;
    public io.ktor.client.request.d l;
    public io.ktor.util.date.d m;
    public /* synthetic */ Object n;
    public final /* synthetic */ f o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.d(null, null, null, null, this);
    }
}
