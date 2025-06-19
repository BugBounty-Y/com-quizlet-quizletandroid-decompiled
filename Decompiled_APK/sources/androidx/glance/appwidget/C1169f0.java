package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1169f0 extends kotlin.coroutines.jvm.internal.c {
    public C1173h0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1173h0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1169f0(C1173h0 c1173h0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c1173h0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return C1173h0.a(this.l, null, this);
    }
}
