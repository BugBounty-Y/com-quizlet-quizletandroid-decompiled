package androidx.compose.foundation;

/* renamed from: androidx.compose.foundation.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0304c0 extends kotlin.coroutines.jvm.internal.c {
    public C0310f0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0310f0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0304c0(C0310f0 c0310f0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0310f0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return C0310f0.N0(this.l, this);
    }
}
