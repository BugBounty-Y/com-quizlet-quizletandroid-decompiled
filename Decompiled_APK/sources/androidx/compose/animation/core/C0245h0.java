package androidx.compose.animation.core;

/* renamed from: androidx.compose.animation.core.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0245h0 extends kotlin.coroutines.jvm.internal.c {
    public C0247i0 j;
    public Object k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0247i0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0245h0(C0247i0 c0247i0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0247i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return C0247i0.X(this.m, this);
    }
}
