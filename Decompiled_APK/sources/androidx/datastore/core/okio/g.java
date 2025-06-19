package androidx.datastore.core.okio;

import okio.x;

/* loaded from: classes.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public Object k;
    public x l;
    public Object m;
    public /* synthetic */ Object n;
    public final /* synthetic */ h o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(null, this);
    }
}
