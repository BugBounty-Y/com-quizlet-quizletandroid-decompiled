package com.braze.managers;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class N implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;

    public /* synthetic */ N(long j, long j2, int i, long j3) {
        this.a = i;
        this.b = j;
        this.c = j2;
        this.d = j3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int i = this.a;
        long j = this.c;
        long j2 = this.d;
        long j3 = this.b;
        switch (i) {
            case 0:
                return C1501n.a(j3, j, j2);
            default:
                return com.braze.triggers.managers.c.a(j3, j, j2);
        }
    }
}
