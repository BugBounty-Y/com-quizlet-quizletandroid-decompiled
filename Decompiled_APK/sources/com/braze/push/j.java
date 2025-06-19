package com.braze.push;

import com.braze.push.BrazePushReceiver;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ j(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$22();
            case 1:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$24();
            case 2:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$26();
            case 3:
                return NotificationTrampolineActivity.onResume$lambda$1();
            case 4:
                return NotificationTrampolineActivity.onResume$lambda$2();
            case 5:
                return NotificationTrampolineActivity.onResume$lambda$5();
            case 6:
                return NotificationTrampolineActivity.onResume$lambda$6();
            case 7:
                return NotificationTrampolineActivity.onCreate$lambda$0();
            default:
                return NotificationTrampolineActivity.onPause$lambda$7();
        }
    }
}
