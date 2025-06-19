package androidx.compose.animation.core;

/* renamed from: androidx.compose.animation.core.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0233b0 extends kotlin.coroutines.jvm.internal.c {
    public C0247i0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0247i0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0233b0(C0247i0 c0247i0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0247i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return C0247i0.V(this.l, this);
    }
}
