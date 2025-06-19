package androidx.compose.foundation.relocation;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.ui.geometry.c j;
    public Object[] k;
    public int l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ c o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.o = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(null, this);
    }
}
