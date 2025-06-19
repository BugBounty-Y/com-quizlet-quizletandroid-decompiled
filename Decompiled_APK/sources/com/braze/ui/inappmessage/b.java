package com.braze.ui.inappmessage;

import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeInAppMessageManager.ensureSubscribedToInAppMessageEvents$lambda$0();
            case 1:
                return BrazeInAppMessageManager.ensureSubscribedToInAppMessageEvents$lambda$1();
            case 2:
                return BrazeInAppMessageManager.ensureSubscribedToInAppMessageEvents$lambda$3();
            case 3:
                return BrazeInAppMessageManager.ensureSubscribedToInAppMessageEvents$lambda$4();
            case 4:
                return BrazeInAppMessageManager.unregisterInAppMessageManager$lambda$22();
            case 5:
                return BrazeInAppMessageManager.ensureSubscribedToInAppMessageEvents$lambda$7();
            case 6:
                return BrazeInAppMessageManager.resumeWebviewIfNecessary$lambda$63();
            case 7:
                return BrazeInAppMessageManager.resetAfterInAppMessageClose$lambda$35();
            case 8:
                return BrazeInAppMessageManager.verifyOrientationStatus$lambda$58();
            case 9:
                return BrazeInAppMessageManager.verifyOrientationStatus$lambda$59();
            case 10:
                return BrazeInAppMessageManager.verifyOrientationStatus$lambda$60();
            case 11:
                return BrazeInAppMessageManager.verifyOrientationStatus$lambda$61();
            case 12:
                return BrazeInAppMessageManager.unregisterInAppMessageManager$lambda$23();
            case 13:
                return BrazeInAppMessageManager.pauseWebviewIfNecessary$lambda$62();
            case 14:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$51$lambda$49();
            case 15:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$51$lambda$50();
            case 16:
                return BrazeInAppMessageManager.registerInAppMessageManager$lambda$9();
            case 17:
                return BrazeInAppMessageManager.registerInAppMessageManager$lambda$11();
            case 18:
                return BrazeInAppMessageManager.registerInAppMessageManager$lambda$14$lambda$13();
            case 19:
                return BrazeInAppMessageManager.registerInAppMessageManager$lambda$16$lambda$15();
            case 20:
                return DefaultInAppMessageViewWrapper.closeInAppMessageView$lambda$26();
            case 21:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$6();
            case EventType.WINDOW_STATE /* 22 */:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$13();
            case EventType.AUDIO /* 23 */:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$14();
            case EventType.VIDEO /* 24 */:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$15();
            case EventType.SUBS /* 25 */:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$12$lambda$8();
            case EventType.CDN /* 26 */:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$12$lambda$9();
            case 27:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$12$lambda$10();
            case 28:
                return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$12$lambda$11();
            default:
                return DefaultInAppMessageViewWrapper.close$lambda$3();
        }
    }
}
