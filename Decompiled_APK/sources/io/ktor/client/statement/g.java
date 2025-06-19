package io.ktor.client.statement;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public io.ktor.client.call.b k;
    public /* synthetic */ Object l;
    public final /* synthetic */ h m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(this);
    }
}
