package androidx.compose.material3;

/* renamed from: androidx.compose.material3.u1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0738u1 extends kotlin.coroutines.jvm.internal.c {
    public C0744v1 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0744v1 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0738u1(C0744v1 c0744v1, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0744v1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(this);
    }
}
