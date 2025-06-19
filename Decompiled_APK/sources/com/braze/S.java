package com.braze;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class S implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ double c;
    public final /* synthetic */ double d;

    public /* synthetic */ S(String str, double d, double d2, int i) {
        this.a = i;
        this.b = str;
        this.c = d;
        this.d = d2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.setLocationCustomAttribute$lambda$66(this.b, this.c, this.d);
            default:
                return com.braze.models.outgoing.event.a.b(this.b, this.c, this.d);
        }
    }
}
