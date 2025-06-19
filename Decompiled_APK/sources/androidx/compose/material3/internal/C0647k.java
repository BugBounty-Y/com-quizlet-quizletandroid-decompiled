package androidx.compose.material3.internal;

/* renamed from: androidx.compose.material3.internal.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0647k extends kotlin.coroutines.jvm.internal.c {
    public androidx.work.impl.model.t j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.work.impl.model.t l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0647k(androidx.work.impl.model.t tVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.c(null, null, this);
    }
}
