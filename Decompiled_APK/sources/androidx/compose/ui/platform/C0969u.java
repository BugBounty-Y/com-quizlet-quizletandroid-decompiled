package androidx.compose.ui.platform;

/* renamed from: androidx.compose.ui.platform.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0969u extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C0971v k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0969u(C0971v c0971v, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = c0971v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        this.k.F(null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
