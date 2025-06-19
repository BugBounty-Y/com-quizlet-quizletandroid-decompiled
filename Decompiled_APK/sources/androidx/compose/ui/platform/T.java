package androidx.compose.ui.platform;

/* loaded from: classes.dex */
public final class T extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ V k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(V v, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        this.k.a(null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
