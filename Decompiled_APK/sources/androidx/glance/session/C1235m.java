package androidx.glance.session;

/* renamed from: androidx.glance.session.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1235m extends kotlin.coroutines.jvm.internal.c {
    public o j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ o m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1235m(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(null, null, this);
    }
}
