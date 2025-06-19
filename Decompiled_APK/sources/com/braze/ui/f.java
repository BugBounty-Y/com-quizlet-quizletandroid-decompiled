package com.braze.ui;

import com.braze.BrazeUser;
import com.braze.enums.NotificationSubscriptionType;
import com.braze.ui.actions.brazeactions.steps.SetEmailSubscriptionStep;
import com.braze.ui.actions.brazeactions.steps.SetPushNotificationSubscriptionStep;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ NotificationSubscriptionType b;

    public /* synthetic */ f(NotificationSubscriptionType notificationSubscriptionType, int i) {
        this.a = i;
        this.b = notificationSubscriptionType;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return UserJavascriptInterfaceBase.setEmailNotificationSubscriptionType$lambda$13(this.b, (BrazeUser) obj);
            case 1:
                return UserJavascriptInterfaceBase.setPushNotificationSubscriptionType$lambda$15(this.b, (BrazeUser) obj);
            case 2:
                return SetEmailSubscriptionStep.run$lambda$2(this.b, (BrazeUser) obj);
            default:
                return SetPushNotificationSubscriptionStep.run$lambda$2(this.b, (BrazeUser) obj);
        }
    }
}
