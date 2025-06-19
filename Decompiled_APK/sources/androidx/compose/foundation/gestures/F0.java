package androidx.compose.foundation.gestures;

/* loaded from: classes.dex */
public final class F0 extends kotlin.coroutines.jvm.internal.c {
    public kotlin.jvm.internal.I j;
    public /* synthetic */ Object k;
    public final /* synthetic */ L0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F0(L0 l0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = l0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(0L, this);
    }
}
