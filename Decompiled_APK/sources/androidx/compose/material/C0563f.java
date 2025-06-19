package androidx.compose.material;

/* renamed from: androidx.compose.material.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0563f extends kotlin.coroutines.jvm.internal.c {
    public C0564g j;
    public Object k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0564g m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0563f(C0564g c0564g, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c0564g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
