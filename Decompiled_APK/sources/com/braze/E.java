package com.braze;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class E implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;

    public /* synthetic */ E(long j, long j2, int i) {
        this.a = i;
        this.b = j;
        this.c = j2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze._init_$lambda$28(this.b, this.c);
            default:
                return com.braze.triggers.managers.c.a(this.b, this.c);
        }
    }
}
