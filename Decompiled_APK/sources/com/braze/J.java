package com.braze;

import android.content.Intent;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class J implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Intent b;

    public /* synthetic */ J(int i, Intent intent) {
        this.a = i;
        this.b = intent;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.logPushNotificationOpened$lambda$58(this.b);
            default:
                return BrazeFlushPushDeliveryReceiver.onReceive$lambda$0(this.b);
        }
    }
}
