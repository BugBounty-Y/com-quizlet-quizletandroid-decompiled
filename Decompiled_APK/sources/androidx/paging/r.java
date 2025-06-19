package androidx.paging;

import androidx.compose.animation.C0297y;

/* loaded from: classes.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public C0297y j;
    public kotlin.jvm.internal.J k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0297y m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(C0297y c0297y, kotlin.coroutines.h hVar) {
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
