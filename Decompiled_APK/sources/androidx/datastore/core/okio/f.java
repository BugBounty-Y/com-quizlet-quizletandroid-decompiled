package androidx.datastore.core.okio;

/* loaded from: classes.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public b k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ h n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.d(null, this);
    }
}
