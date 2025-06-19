package com.braze;

import android.content.Intent;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class I implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Intent b;
    public final /* synthetic */ Braze c;

    public /* synthetic */ I(Intent intent, Braze braze, int i) {
        this.a = i;
        this.b = intent;
        this.c = braze;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.handleInAppMessageTestPush$lambda$189(this.b, this.c);
            default:
                return Braze.logPushNotificationOpened$lambda$62(this.b, this.c);
        }
    }
}
