package coil3.intercept;

import androidx.camera.core.a0;

/* loaded from: classes.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public a0 j;
    public h k;
    public /* synthetic */ Object l;
    public final /* synthetic */ a0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(a0 a0Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = a0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.f(this);
    }
}
