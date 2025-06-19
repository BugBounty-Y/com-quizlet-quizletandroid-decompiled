package com.quizlet.features.blocks.ui;

import android.webkit.WebView;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ c(Function0 function0, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = function0;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                InterfaceC0773a0 interfaceC0773a0 = this.c;
                WebView webView = (WebView) interfaceC0773a0.getValue();
                if (webView == null || !webView.canGoBack()) {
                    this.b.invoke();
                } else {
                    WebView webView2 = (WebView) interfaceC0773a0.getValue();
                    if (webView2 != null) {
                        webView2.goBack();
                    }
                }
                break;
            case 1:
                this.c.setValue("");
                this.b.invoke();
                break;
            case 2:
                this.c.setValue("");
                this.b.invoke();
                break;
            case 3:
                this.c.setValue("");
                this.b.invoke();
                break;
            case 4:
                this.c.setValue(Boolean.TRUE);
                this.b.invoke();
                break;
            case 5:
                this.c.setValue(Boolean.TRUE);
                this.b.invoke();
                break;
            case 6:
                this.c.setValue(Boolean.TRUE);
                this.b.invoke();
                break;
            case 7:
                this.c.setValue(Boolean.TRUE);
                this.b.invoke();
                break;
            case 8:
                this.c.setValue(Boolean.TRUE);
                this.b.invoke();
                break;
            case 9:
                this.b.invoke();
                this.c.setValue(Boolean.FALSE);
                break;
            case 10:
                this.b.invoke();
                this.c.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 11:
                this.c.setValue(Boolean.FALSE);
                this.b.invoke();
                break;
            case 12:
                this.c.setValue(Boolean.FALSE);
                this.b.invoke();
                break;
            case 13:
                this.c.setValue("");
                this.b.invoke();
                break;
            default:
                this.c.setValue("");
                this.b.invoke();
                break;
        }
        return Unit.a;
    }
}
