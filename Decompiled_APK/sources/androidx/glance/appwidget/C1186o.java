package androidx.glance.appwidget;

import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1186o extends kotlin.coroutines.jvm.internal.c {
    public Function2 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1188p l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1186o(C1188p c1188p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c1188p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        this.l.b(null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
