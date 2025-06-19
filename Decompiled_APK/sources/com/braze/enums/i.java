package com.braze.enums;

import androidx.compose.runtime.C0776c;
import androidx.compose.ui.text.input.A;
import com.braze.enums.Month;
import com.braze.managers.C1496i;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.push.BrazeNotificationUtils;
import com.braze.push.BrazePushReceiver;
import com.braze.support.BrazeLogger;
import com.braze.support.PermissionUtils;
import com.braze.support.ValidationUtils;
import com.braze.support.k;
import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.braze.ui.inappmessage.DefaultInAppMessageViewWrapper;
import com.braze.ui.inappmessage.views.InAppMessageHtmlBaseView;
import com.braze.ui.inappmessage.views.InAppMessageImmersiveBaseView;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;

    public /* synthetic */ i(int i, int i2) {
        this.a = i2;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Month.Companion.getMonth$lambda$2$lambda$1(this.b);
            case 1:
                return C1496i.a(this.b);
            case 2:
                return C1496i.b(this.b);
            case 3:
                return InAppMessageBase._set_durationInMilliseconds_$lambda$0(this.b);
            case 4:
                return InAppMessageBase._set_durationInMilliseconds_$lambda$1(this.b);
            case 5:
                return BrazeNotificationUtils.getNotificationId$lambda$20(this.b);
            case 6:
                return BrazeNotificationUtils.setNotificationDurationAlarm$lambda$16(this.b);
            case 7:
                return BrazeNotificationUtils.cancelNotification$lambda$64(this.b);
            case 8:
                return BrazeNotificationUtils.handleCancelNotificationAction$lambda$62(this.b);
            case 9:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$12(this.b);
            case 10:
                return BrazeLogger._set_logLevel_$lambda$0(this.b);
            case 11:
                return PermissionUtils.incrementPermissionRequestCount$lambda$11(this.b);
            case 12:
                return PermissionUtils.wouldPushPermissionPromptDisplay$lambda$7(this.b);
            case 13:
                return PermissionUtils.wouldPushPermissionPromptDisplay$lambda$9(this.b);
            case 14:
                return ValidationUtils.isValidLogPurchaseInput$lambda$6(this.b);
            case 15:
                return ValidationUtils.isValidLogPurchaseInput$lambda$7(this.b);
            case 16:
                return k.a(this.b);
            case 17:
                return com.braze.triggers.managers.c.a(this.b);
            case 18:
                return ContentCardAdapter.onViewAttachedToWindow$lambda$1(this.b);
            case 19:
                return ContentCardAdapter.onViewDetachedFromWindow$lambda$2(this.b);
            case 20:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$7(this.b);
            case 21:
                return DefaultInAppMessageViewWrapper.open$lambda$1(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return InAppMessageHtmlBaseView._get_messageWebView_$lambda$2(this.b);
            case EventType.AUDIO /* 23 */:
                return InAppMessageImmersiveBaseView.setupDirectionalNavigation$lambda$1(this.b);
            case EventType.VIDEO /* 24 */:
                return Float.valueOf(this.b / 100.0f);
            default:
                return C0776c.z(new A(6, 0L, String.valueOf(this.b)));
        }
    }
}
