package org.prebid.mobile.rendering.views.browser;

import android.webkit.WebView;
import android.webkit.WebViewClient;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.utils.url.UrlHandler;
import org.prebid.mobile.rendering.utils.url.action.DeepLinkAction;
import org.prebid.mobile.rendering.utils.url.action.DeepLinkPlusAction;

/* loaded from: classes3.dex */
class AdBrowserActivityWebViewClient extends WebViewClient {
    public static final /* synthetic */ int c = 0;
    public AdBrowserActivity a;
    public boolean b;

    @Override // android.webkit.WebViewClient
    public final void onPageFinished(WebView webView, String str) {
        final BrowserControls browserControls;
        AdBrowserActivity adBrowserActivity = this.a;
        if (adBrowserActivity != null && (browserControls = adBrowserActivity.c) != null) {
            browserControls.h.post(new Runnable() { // from class: org.prebid.mobile.rendering.views.browser.a
                @Override // java.lang.Runnable
                public final void run() {
                    BrowserControls browserControls2 = browserControls;
                    BrowserControlsEventsListener browserControlsEventsListener = browserControls2.i;
                    if (browserControlsEventsListener == null) {
                        LogUtil.b("BrowserControls", "updateNavigationButtonsState: Unable to update state. browserControlsEventsListener is null");
                        return;
                    }
                    WebView webView2 = AdBrowserActivity.this.a;
                    if (webView2 != null ? webView2.canGoBack() : false) {
                        browserControls2.b.setBackgroundResource(2131231741);
                    } else {
                        browserControls2.b.setBackgroundResource(2131231742);
                    }
                    WebView webView3 = AdBrowserActivity.this.a;
                    if (webView3 != null ? webView3.canGoForward() : false) {
                        browserControls2.c.setBackgroundResource(2131231745);
                    } else {
                        browserControls2.c.setBackgroundResource(2131231746);
                    }
                }
            });
        }
        super.onPageFinished(webView, str);
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, String str) {
        UrlHandler.Builder builder = new UrlHandler.Builder();
        builder.a.add(new DeepLinkPlusAction());
        builder.a.add(new DeepLinkAction());
        builder.b = new UrlHandler.UrlHandlerResultListener() { // from class: org.prebid.mobile.rendering.views.browser.AdBrowserActivityWebViewClient.1
            @Override // org.prebid.mobile.rendering.utils.url.UrlHandler.UrlHandlerResultListener
            public final void a(String str2) {
                int i = AdBrowserActivityWebViewClient.c;
                LogUtil.e(3, "AdBrowserActivityWebViewClient", "Failed to handleUrl: " + str2);
                AdBrowserActivityWebViewClient.this.b = false;
            }

            @Override // org.prebid.mobile.rendering.utils.url.UrlHandler.UrlHandlerResultListener
            public final void onSuccess() {
                AdBrowserActivityWebViewClient adBrowserActivityWebViewClient = AdBrowserActivityWebViewClient.this;
                adBrowserActivityWebViewClient.b = false;
                AdBrowserActivity adBrowserActivity = adBrowserActivityWebViewClient.a;
                if (adBrowserActivity != null) {
                    adBrowserActivity.finish();
                }
            }
        };
        UrlHandler urlHandler = new UrlHandler(builder.a, builder.b);
        if (this.b) {
            return false;
        }
        this.b = true;
        return urlHandler.a(webView.getContext(), str, null);
    }
}
