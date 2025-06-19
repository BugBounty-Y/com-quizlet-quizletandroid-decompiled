package coil3.intercept;

import coil3.request.m;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public coil3.fetch.i k;
    public coil3.d l;
    public coil3.request.g m;
    public Object n;
    public m o;
    public coil3.f p;
    public int q;
    public /* synthetic */ Object r;
    public final /* synthetic */ h s;
    public int t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.s = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.r = obj;
        this.t |= Integer.MIN_VALUE;
        return h.a(this.s, null, null, null, null, null, null, this);
    }
}
