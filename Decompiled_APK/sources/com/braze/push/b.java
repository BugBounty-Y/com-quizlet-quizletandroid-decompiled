package com.braze.push;

import android.os.Bundle;
import com.braze.push.BrazePushReceiver;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Bundle b;

    public /* synthetic */ b(Bundle bundle, int i) {
        this.a = i;
        this.b = bundle;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationActionUtils.addNotificationAction$lambda$10(this.b);
            default:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$13(this.b);
        }
    }
}
