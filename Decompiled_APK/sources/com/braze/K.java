package com.braze;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class K implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Braze b;
    public final /* synthetic */ String c;

    public /* synthetic */ K(Braze braze, String str, int i) {
        this.a = i;
        this.b = braze;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.logPushMaxCampaign$lambda$207(this.b, this.c);
            default:
                return Braze._set_registeredPushToken_$lambda$36(this.b, this.c);
        }
    }
}
