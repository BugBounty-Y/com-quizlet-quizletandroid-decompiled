package assistantMode.grading;

/* loaded from: classes.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public l j;
    public grading.core.b k;
    public long l;
    public /* synthetic */ Object m;
    public final /* synthetic */ l n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(l lVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.a(null, null, null, null, null, this);
    }
}
