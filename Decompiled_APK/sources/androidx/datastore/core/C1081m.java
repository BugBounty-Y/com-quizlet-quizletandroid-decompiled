package androidx.datastore.core;

import kotlin.jvm.functions.Function0;

/* renamed from: androidx.datastore.core.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1081m extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ P b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1081m(P p, int i) {
        super(0);
        this.a = i;
        this.b = p;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return ((n0) this.b.j.getValue()).c();
            default:
                return this.b.a.a();
        }
    }
}
