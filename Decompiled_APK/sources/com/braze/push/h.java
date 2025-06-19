package com.braze.push;

import android.content.Intent;
import com.braze.push.BrazePushReceiver;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Intent b;

    public /* synthetic */ h(int i, Intent intent) {
        this.a = i;
        this.b = intent;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationUtils.routeUserWithNotificationOpenedIntent$lambda$8(this.b);
            case 1:
                return BrazeNotificationUtils.sendPushActionIntent$lambda$80(this.b);
            case 2:
                return BrazePushReceiver.Companion.handleAdmRegistrationEventIfEnabled$lambda$4(this.b);
            case 3:
                return BrazePushReceiver.Companion.handlePush$performWork$lambda$0(this.b);
            case 4:
                return BrazePushReceiver.Companion.handlePush$performWork$lambda$1(this.b);
            default:
                return NotificationTrampolineActivity.onResume$lambda$3(this.b);
        }
    }
}
