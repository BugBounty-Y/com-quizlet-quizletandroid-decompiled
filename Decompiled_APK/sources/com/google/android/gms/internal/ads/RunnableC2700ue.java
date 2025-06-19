package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ue, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2700ue implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ ViewTreeObserverOnGlobalLayoutListenerC2829xe b;

    public /* synthetic */ RunnableC2700ue(ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe, int i) {
        this.a = i;
        this.b = viewTreeObserverOnGlobalLayoutListenerC2829xe;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.destroy();
                break;
            case 1:
                super/*android.webkit.WebView*/.loadUrl("about:blank");
                break;
            default:
                super/*android.webkit.WebView*/.destroy();
                break;
        }
    }
}
