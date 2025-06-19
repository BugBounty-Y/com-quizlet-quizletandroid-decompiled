package com.braze;

import com.braze.enums.NotificationSubscriptionType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class T implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ NotificationSubscriptionType b;

    public /* synthetic */ T(NotificationSubscriptionType notificationSubscriptionType, int i) {
        this.a = i;
        this.b = notificationSubscriptionType;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.setEmailNotificationSubscriptionType$lambda$25(this.b);
            default:
                return BrazeUser.setPushNotificationSubscriptionType$lambda$26(this.b);
        }
    }
}
