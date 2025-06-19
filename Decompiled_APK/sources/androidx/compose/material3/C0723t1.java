package androidx.compose.material3;

/* renamed from: androidx.compose.material3.t1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0723t1 extends kotlin.coroutines.jvm.internal.c {
    public C0744v1 j;
    public androidx.compose.foundation.interaction.j k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0744v1 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0723t1(C0744v1 c0744v1, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0744v1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(null, this);
    }
}
