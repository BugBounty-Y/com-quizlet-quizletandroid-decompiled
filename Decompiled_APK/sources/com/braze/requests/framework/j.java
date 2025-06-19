package com.braze.requests.framework;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;
    public final /* synthetic */ long c;

    public /* synthetic */ j(b bVar, long j, int i) {
        this.a = i;
        this.b = bVar;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.d(this.b, this.c);
            case 1:
                return b.c(this.b, this.c);
            case 2:
                return b.a(this.b, this.c);
            default:
                return b.b(this.b, this.c);
        }
    }
}
