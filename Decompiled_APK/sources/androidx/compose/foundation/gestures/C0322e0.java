package androidx.compose.foundation.gestures;

/* renamed from: androidx.compose.foundation.gestures.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0322e0 extends kotlin.coroutines.jvm.internal.c {
    public C0326g0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0326g0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0322e0(C0326g0 c0326g0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0326g0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(this);
    }
}
