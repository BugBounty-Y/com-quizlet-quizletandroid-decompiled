package com.braze.ui;

import android.webkit.ConsoleMessage;
import com.braze.ui.BrazeWebViewActivity;
import com.braze.ui.inappmessage.views.InAppMessageHtmlBaseView$messageWebView$7;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ConsoleMessage b;

    public /* synthetic */ c(ConsoleMessage consoleMessage, int i) {
        this.a = i;
        this.b = consoleMessage;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeWebViewActivity.AnonymousClass1.onConsoleMessage$lambda$0(this.b);
            default:
                return InAppMessageHtmlBaseView$messageWebView$7.onConsoleMessage$lambda$0(this.b);
        }
    }
}
