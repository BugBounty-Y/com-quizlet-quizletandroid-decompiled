package androidx.datastore.core;

/* loaded from: classes.dex */
public final class N extends kotlin.coroutines.jvm.internal.c {
    public kotlin.jvm.internal.H j;
    public /* synthetic */ Object k;
    public final /* synthetic */ P l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(P p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.j(null, false, this);
    }
}
