package com.braze.ui.inappmessage;

import android.app.Activity;
import android.window.OnBackInvokedCallback;
import com.braze.support.BrazeLogger;
import com.braze.ui.inappmessage.utils.InAppMessageViewUtils;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;

@Metadata
/* loaded from: classes.dex */
public final class DefaultInAppMessageViewWrapper$open$4$dismissInAppMessageCallback$1 implements OnBackInvokedCallback {
    final /* synthetic */ Activity $it;

    public DefaultInAppMessageViewWrapper$open$4$dismissInAppMessageCallback$1(Activity activity) {
        this.$it = activity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onBackInvoked$lambda$0() {
        return "Back button intercepted by in-app message default view wrapper";
    }

    public void onBackInvoked() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new e(7), 7, (Object) null);
        InAppMessageViewUtils.closeInAppMessageOnKeycodeBack();
        this.$it.getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(this);
    }
}
