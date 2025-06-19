package androidx.glance.session;

/* loaded from: classes.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ SessionWorker k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(SessionWorker sessionWorker, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = sessionWorker;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.a(this);
    }
}
