package com.braze.ui.inappmessage;

import com.braze.ui.inappmessage.DefaultInAppMessageViewWrapper;
import com.braze.ui.inappmessage.factories.DefaultInAppMessageHtmlFullViewFactory;
import com.braze.ui.inappmessage.factories.DefaultInAppMessageHtmlViewFactory;
import com.braze.ui.inappmessage.factories.DefaultInAppMessageModalViewFactory;
import com.braze.ui.inappmessage.factories.DefaultInAppMessageSlideupViewFactory;
import com.braze.ui.inappmessage.listeners.DefaultInAppMessageViewLifecycleListener;
import com.braze.ui.inappmessage.listeners.DefaultInAppMessageWebViewClientListener;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return DefaultInAppMessageViewWrapper.close$lambda$5$lambda$4();
            case 1:
                return DefaultInAppMessageViewWrapper.createButtonClickListeners$lambda$21$lambda$17();
            case 2:
                return DefaultInAppMessageViewWrapper.open$lambda$0();
            case 3:
                return DefaultInAppMessageViewWrapper.closeInAppMessageView$lambda$24();
            case 4:
                return DefaultInAppMessageViewWrapper.Companion.setAllViewGroupChildrenAsNonAccessibilityImportant$lambda$0();
            case 5:
                return DefaultInAppMessageViewWrapper.Companion.resetAllViewGroupChildrenToPreviousAccessibilityFlagOrAuto$lambda$1();
            case 6:
                return DefaultInAppMessageViewWrapper.AnonymousClass1.onAnimationEnd$lambda$0();
            case 7:
                return DefaultInAppMessageViewWrapper$open$4$dismissInAppMessageCallback$1.onBackInvoked$lambda$0();
            case 8:
                return DefaultInAppMessageHtmlFullViewFactory.createInAppMessageView$lambda$0();
            case 9:
                return DefaultInAppMessageHtmlViewFactory.createInAppMessageView$lambda$0();
            case 10:
                return DefaultInAppMessageModalViewFactory.createInAppMessageView$lambda$2$lambda$1();
            case 11:
                return DefaultInAppMessageSlideupViewFactory.createInAppMessageView$lambda$0();
            case 12:
                return DefaultInAppMessageViewLifecycleListener.onDismissed$lambda$8();
            case 13:
                return DefaultInAppMessageViewLifecycleListener.performClickAction$lambda$11();
            case 14:
                return DefaultInAppMessageViewLifecycleListener.beforeOpened$lambda$0();
            case 15:
                return DefaultInAppMessageViewLifecycleListener.afterClosed$lambda$3();
            case 16:
                return DefaultInAppMessageViewLifecycleListener.onButtonClicked$lambda$7();
            case 17:
                return DefaultInAppMessageViewLifecycleListener.beforeClosed$lambda$2();
            case 18:
                return DefaultInAppMessageViewLifecycleListener.onClicked$lambda$4();
            case 19:
                return DefaultInAppMessageViewLifecycleListener.onClicked$lambda$5();
            case 20:
                return DefaultInAppMessageViewLifecycleListener.onClicked$lambda$6();
            case 21:
                return DefaultInAppMessageViewLifecycleListener.afterOpened$lambda$1();
            case EventType.WINDOW_STATE /* 22 */:
                return DefaultInAppMessageViewLifecycleListener.performClickAction$lambda$9();
            case EventType.AUDIO /* 23 */:
                return DefaultInAppMessageViewLifecycleListener.performClickAction$lambda$10();
            case EventType.VIDEO /* 24 */:
                return DefaultInAppMessageWebViewClientListener.onOtherUrlAction$lambda$8();
            case EventType.SUBS /* 25 */:
                return DefaultInAppMessageWebViewClientListener.onNewsfeedAction$lambda$3();
            case EventType.CDN /* 26 */:
                return DefaultInAppMessageWebViewClientListener.onCloseAction$lambda$0();
            case 27:
                return DefaultInAppMessageWebViewClientListener.onCloseAction$lambda$1();
            case 28:
                return DefaultInAppMessageWebViewClientListener.onCustomEventAction$lambda$5();
            default:
                return DefaultInAppMessageWebViewClientListener.onCustomEventAction$lambda$6();
        }
    }
}
