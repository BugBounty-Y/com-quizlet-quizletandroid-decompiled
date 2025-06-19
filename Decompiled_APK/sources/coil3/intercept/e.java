package coil3.intercept;

import coil3.request.m;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public coil3.d k;
    public coil3.request.g l;
    public Object m;
    public m n;
    public coil3.f o;
    public int p;
    public /* synthetic */ Object q;
    public final /* synthetic */ h r;
    public int s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.r = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.q = obj;
        this.s |= Integer.MIN_VALUE;
        return this.r.c(null, null, null, null, null, this);
    }
}
