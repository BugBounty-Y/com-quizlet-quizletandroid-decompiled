package androidx.compose.ui.contentcapture;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public c j;
    public kotlinx.coroutines.channels.c k;
    public /* synthetic */ Object l;
    public final /* synthetic */ c m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(this);
    }
}
