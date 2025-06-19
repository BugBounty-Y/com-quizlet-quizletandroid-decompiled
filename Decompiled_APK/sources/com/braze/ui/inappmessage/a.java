package com.braze.ui.inappmessage;

import com.braze.models.inappmessage.IInAppMessage;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ IInAppMessage b;

    public /* synthetic */ a(IInAppMessage iInAppMessage, int i) {
        this.a = i;
        this.b = iInAppMessage;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$33(this.b);
            case 1:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$37(this.b);
            case 2:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$52(this.b);
            default:
                return InAppMessageManagerBase.getDefaultInAppMessageViewFactory$lambda$1(this.b);
        }
    }
}
