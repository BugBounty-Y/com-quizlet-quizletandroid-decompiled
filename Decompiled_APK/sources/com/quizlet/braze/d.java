package com.quizlet.braze;

import com.braze.BrazeUser;
import com.braze.enums.NotificationSubscriptionType;
import com.braze.events.SimpleValueCallback;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends SimpleValueCallback {
    public final /* synthetic */ NotificationSubscriptionType a;

    public d(NotificationSubscriptionType notificationSubscriptionType) {
        this.a = notificationSubscriptionType;
    }

    @Override // com.braze.events.IValueCallback
    public final void onSuccess(Object obj) {
        BrazeUser value = (BrazeUser) obj;
        Intrinsics.checkNotNullParameter(value, "value");
        value.setPushNotificationSubscriptionType(this.a);
    }
}
