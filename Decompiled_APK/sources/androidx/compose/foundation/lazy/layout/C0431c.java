package androidx.compose.foundation.lazy.layout;

/* renamed from: androidx.compose.foundation.lazy.layout.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0431c extends kotlin.coroutines.jvm.internal.c {
    public kotlin.coroutines.p j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0432d l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0431c(C0432d c0432d, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0432d;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.l(this);
    }
}
