package androidx.compose.foundation;

/* renamed from: androidx.compose.foundation.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0302b0 extends kotlin.coroutines.jvm.internal.c {
    public C0310f0 j;
    public androidx.compose.foundation.interaction.h k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0310f0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0302b0(C0310f0 c0310f0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0310f0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return C0310f0.M0(this.m, this);
    }
}
