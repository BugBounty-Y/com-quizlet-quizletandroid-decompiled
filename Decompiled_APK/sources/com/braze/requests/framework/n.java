package com.braze.requests.framework;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class n implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ Object e;

    public /* synthetic */ n(h hVar, long j, long j2, Object obj, int i) {
        this.a = i;
        this.b = hVar;
        this.c = j;
        this.d = j2;
        this.e = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int i = this.a;
        long j = this.d;
        switch (i) {
            case 0:
                return b.a(this.b, this.c, j, (com.braze.requests.util.d) this.e);
            default:
                return g.a(this.b, this.c, j, (g) this.e);
        }
    }
}
