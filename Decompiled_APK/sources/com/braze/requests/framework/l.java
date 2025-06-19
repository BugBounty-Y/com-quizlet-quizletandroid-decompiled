package com.braze.requests.framework;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class l implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;
    public final /* synthetic */ long c;

    public /* synthetic */ l(long j, h hVar) {
        this.a = 2;
        this.c = j;
        this.b = hVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.a(this.b, this.c);
            case 1:
                return e.a(this.b, this.c);
            case 2:
                return g.b(this.c, this.b);
            case 3:
                return h.a(this.b, this.c);
            default:
                return com.braze.requests.framework.queue.i.b(this.b, this.c);
        }
    }

    public /* synthetic */ l(h hVar, long j, int i) {
        this.a = i;
        this.b = hVar;
        this.c = j;
    }
}
