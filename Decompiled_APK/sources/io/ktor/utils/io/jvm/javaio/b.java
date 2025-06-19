package io.ktor.utils.io.jvm.javaio;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public d j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ d m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.e(0, this);
    }
}
