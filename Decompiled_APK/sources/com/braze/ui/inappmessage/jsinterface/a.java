package com.braze.ui.inappmessage.jsinterface;

import com.braze.ui.inappmessage.jsinterface.InAppMessageJavascriptInterface;
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
                return InAppMessageJavascriptInterface.AnonymousClass1.invokeSuspend$lambda$0();
            default:
                return InAppMessageJavascriptInterface.AnonymousClass1.C00011.invokeSuspend$lambda$0();
        }
    }
}
