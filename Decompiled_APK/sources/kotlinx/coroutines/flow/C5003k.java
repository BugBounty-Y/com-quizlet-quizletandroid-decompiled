package kotlinx.coroutines.flow;

import androidx.datastore.core.C1087t;

/* renamed from: kotlinx.coroutines.flow.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5003k extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C1087t l;
    public C1087t m;
    public InterfaceC5002j n;
    public int o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5003k(C1087t c1087t, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c1087t;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.b(null, this);
    }
}
