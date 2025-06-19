package coil3.intercept;

import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public coil3.request.g k;
    public Object l;
    public Object m;
    public J n;
    public J o;
    public J p;
    public J q;
    public /* synthetic */ Object r;
    public final /* synthetic */ h s;
    public int t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.s = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.r = obj;
        this.t |= Integer.MIN_VALUE;
        return h.b(this.s, null, null, null, null, this);
    }
}
