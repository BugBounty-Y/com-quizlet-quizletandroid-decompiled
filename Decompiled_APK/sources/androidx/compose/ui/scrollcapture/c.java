package androidx.compose.ui.scrollcapture;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public f j;
    public Object k;
    public androidx.compose.ui.unit.i l;
    public int m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ f p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return f.a(this.p, null, null, this);
    }
}
