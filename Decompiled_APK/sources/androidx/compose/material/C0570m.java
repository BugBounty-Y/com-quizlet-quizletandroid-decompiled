package androidx.compose.material;

/* renamed from: androidx.compose.material.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0570m extends kotlin.coroutines.jvm.internal.c {
    public C0575s j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0575s l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0570m(C0575s c0575s, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0575s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(null, null, null, this);
    }
}
