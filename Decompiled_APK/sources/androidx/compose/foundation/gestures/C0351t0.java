package androidx.compose.foundation.gestures;

/* renamed from: androidx.compose.foundation.gestures.t0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0351t0 extends kotlin.coroutines.jvm.internal.c {
    public long j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0353u0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0351t0(C0353u0 c0353u0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0353u0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.p(0L, 0L, this);
    }
}
