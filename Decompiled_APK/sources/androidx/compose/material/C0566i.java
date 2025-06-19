package androidx.compose.material;

/* renamed from: androidx.compose.material.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0566i extends kotlin.coroutines.jvm.internal.c {
    public C0575s j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0575s l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0566i(C0575s c0575s, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0575s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, null, this);
    }
}
