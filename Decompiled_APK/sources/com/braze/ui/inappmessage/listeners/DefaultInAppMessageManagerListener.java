package com.braze.ui.inappmessage.listeners;

import android.content.Context;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.inappmessage.IInAppMessageThemeable;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.braze.ui.inappmessage.InAppMessageOperation;
import com.braze.ui.support.ViewUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class DefaultInAppMessageManagerListener implements IInAppMessageManagerListener {
    @Override // com.braze.ui.inappmessage.listeners.IInAppMessageManagerListener
    @NotNull
    public InAppMessageOperation beforeInAppMessageDisplayed(@NotNull IInAppMessage inAppMessage) {
        Context applicationContext;
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        if ((inAppMessage instanceof IInAppMessageThemeable) && (applicationContext = BrazeInAppMessageManager.Companion.getInstance().getApplicationContext()) != null && ViewUtils.isDeviceInNightMode(applicationContext)) {
            ((IInAppMessageThemeable) inAppMessage).enableDarkTheme();
        }
        return InAppMessageOperation.DISPLAY_NOW;
    }
}
