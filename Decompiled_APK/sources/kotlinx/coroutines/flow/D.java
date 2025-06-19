package kotlinx.coroutines.flow;

import androidx.compose.animation.C0297y;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.c {
    public C0297y j;
    public Object k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0297y m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(C0297y c0297y, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c0297y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
