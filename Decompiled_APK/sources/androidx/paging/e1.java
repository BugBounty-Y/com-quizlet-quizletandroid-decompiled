package androidx.paging;

/* loaded from: classes.dex */
public final class e1 extends kotlin.coroutines.jvm.internal.c {
    public androidx.appcompat.app.L j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.appcompat.app.L l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e1(androidx.appcompat.app.L l, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.P(0, null, this);
    }
}
