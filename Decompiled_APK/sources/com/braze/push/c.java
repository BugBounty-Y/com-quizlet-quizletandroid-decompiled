package com.braze.push;

import com.braze.models.push.BrazeNotificationPayload;
import com.braze.push.BrazeNotificationFactory;
import com.braze.push.BrazePushReceiver;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ BrazeNotificationPayload b;

    public /* synthetic */ c(BrazeNotificationPayload brazeNotificationPayload, int i) {
        this.a = i;
        this.b = brazeNotificationPayload;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationFactory.Companion.populateNotificationBuilder$lambda$0(this.b);
            case 1:
                return BrazeNotificationUtils.setPublicVersionIfPresentAndSupported$lambda$58(this.b);
            default:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$21(this.b);
        }
    }
}
