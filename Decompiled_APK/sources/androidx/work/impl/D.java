package androidx.work.impl;

/* loaded from: classes.dex */
public final class D extends kotlin.coroutines.jvm.internal.c {
    public F j;
    public /* synthetic */ Object k;
    public final /* synthetic */ F l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(F f, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return F.a(this.l, this);
    }
}
