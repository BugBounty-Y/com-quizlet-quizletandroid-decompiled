package coil3.intercept;

import androidx.camera.core.a0;

/* loaded from: classes.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public a0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ h l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.d(null, this);
    }
}
