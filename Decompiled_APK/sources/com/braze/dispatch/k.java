package com.braze.dispatch;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ f c;

    public /* synthetic */ k(long j, f fVar, int i) {
        this.a = i;
        this.b = j;
        this.c = fVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f.a(this.b, this.c);
            default:
                return f.b(this.b, this.c);
        }
    }
}
