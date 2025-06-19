package io.ktor.utils.io;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public k j;
    public k k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ k n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.e(0, this);
    }
}
