package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1180l extends kotlin.coroutines.jvm.internal.c {
    public C1170g j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1182m l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1180l(C1182m c1182m, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c1182m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.f(this);
    }
}
