package com.braze.ui.inappmessage.utils;

import com.braze.ui.inappmessage.utils.BackgroundInAppMessagePreparer;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BackgroundInAppMessagePreparer.AnonymousClass2.invokeSuspend$lambda$0();
            case 1:
                return BackgroundInAppMessagePreparer.AnonymousClass1.invokeSuspend$lambda$0();
            case 2:
                return BackgroundInAppMessagePreparer.AnonymousClass1.invokeSuspend$lambda$1();
            case 3:
                return BackgroundInAppMessagePreparer.prepareInAppMessage$lambda$0();
            case 4:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithBitmapDownload$lambda$10();
            case 5:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithBitmapDownload$lambda$11();
            case 6:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithBitmapDownload$lambda$13();
            case 7:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithBitmapDownload$lambda$14();
            case 8:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithHtml$lambda$17();
            case 9:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithHtml$lambda$18();
            case 10:
                return BackgroundInAppMessagePreparer.prepareInAppMessage$lambda$1();
            case 11:
                return BackgroundInAppMessagePreparer.prepareInAppMessage$lambda$2();
            case 12:
                return BackgroundInAppMessagePreparer.prepareInAppMessage$lambda$3();
            case 13:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithZippedAssetHtml$lambda$5();
            case 14:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithZippedAssetHtml$lambda$6();
            case 15:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithBitmapDownload$lambda$9();
            case 16:
                return InAppMessageViewUtils.closeInAppMessageOnKeycodeBack$lambda$3();
            case 17:
                return InAppMessageViewUtils.setIcon$lambda$0();
            default:
                return InAppMessageViewUtils.setDrawableColor$lambda$2();
        }
    }
}
