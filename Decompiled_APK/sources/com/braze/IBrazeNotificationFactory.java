package com.braze;

import android.app.Notification;
import com.braze.models.push.BrazeNotificationPayload;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IBrazeNotificationFactory {
    Notification createNotification(BrazeNotificationPayload brazeNotificationPayload);
}
