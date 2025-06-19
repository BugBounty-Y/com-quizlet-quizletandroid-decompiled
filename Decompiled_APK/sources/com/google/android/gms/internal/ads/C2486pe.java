package com.google.android.gms.internal.ads;

import android.R;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.os.Message;
import android.view.KeyEvent;
import android.view.View;
import android.view.WindowManager;
import android.webkit.ConsoleMessage;
import android.webkit.GeolocationPermissions;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.WebChromeClient;
import android.webkit.WebStorage;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.quizletandroid.databinding.C4607k;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.ads.pe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2486pe extends WebChromeClient {
    public final /* synthetic */ int a = 0;
    public final KeyEvent.Callback b;

    public C2486pe(C2743ve c2743ve) {
        this.b = c2743ve;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final Context b(WebView webView) {
        if (!(webView instanceof InterfaceC2529qe)) {
            return webView.getContext();
        }
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) webView;
        Activity activityZzi = interfaceC2529qe.zzi();
        return activityZzi != null ? activityZzi : interfaceC2529qe.getContext();
    }

    public boolean a(Context context, String str, String str2, String str3, String str4, JsResult jsResult, JsPromptResult jsPromptResult, boolean z) {
        C1669Be c1669Be;
        com.google.android.gms.ads.internal.a aVar;
        try {
            C2743ve c2743ve = (C2743ve) this.b;
            if (c2743ve != null && (c1669Be = c2743ve.a.n) != null && (aVar = c1669Be.w) != null && aVar != null && !aVar.b()) {
                aVar.a("window." + str + "('" + str3 + "')");
                return false;
            }
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            AlertDialog.Builder builderJ = com.google.android.gms.ads.internal.util.F.j(context);
            builderJ.setTitle(str2);
            if (!z) {
                builderJ.setMessage(str3).setPositiveButton(R.string.ok, new DialogInterfaceOnClickListenerC2400ne(jsResult, 1)).setNegativeButton(R.string.cancel, new DialogInterfaceOnClickListenerC2400ne(jsResult, 0)).setOnCancelListener(new DialogInterfaceOnCancelListenerC2357me(jsResult, 0)).create().show();
                return true;
            }
            LinearLayout linearLayout = new LinearLayout(context);
            linearLayout.setOrientation(1);
            TextView textView = new TextView(context);
            textView.setText(str3);
            EditText editText = new EditText(context);
            editText.setText(str4);
            linearLayout.addView(textView);
            linearLayout.addView(editText);
            builderJ.setView(linearLayout).setPositiveButton(R.string.ok, new DialogInterfaceOnClickListenerC2194im(2, jsPromptResult, editText)).setNegativeButton(R.string.cancel, new DialogInterfaceOnClickListenerC2440ob(jsPromptResult, 1)).setOnCancelListener(new DialogInterfaceOnCancelListenerC2357me(jsPromptResult, 1)).create().show();
            return true;
        } catch (WindowManager.BadTokenException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Fail to display Dialog.", e);
            return true;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.webkit.WebChromeClient
    public void onCloseWindow(WebView webView) {
        switch (this.a) {
            case 0:
                if (!(webView instanceof InterfaceC2529qe)) {
                    com.google.android.gms.ads.internal.util.client.i.h("Tried to close a WebView that wasn't an AdWebView.");
                    break;
                } else {
                    com.google.android.gms.ads.internal.overlay.d dVarQ = ((InterfaceC2529qe) webView).Q();
                    if (dVarQ != null) {
                        dVarQ.b();
                        break;
                    } else {
                        com.google.android.gms.ads.internal.util.client.i.h("Tried to close an AdWebView not associated with an overlay.");
                        break;
                    }
                }
            default:
                super.onCloseWindow(webView);
                break;
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
        switch (this.a) {
            case 0:
                String strMessage = consoleMessage.message();
                String strSourceId = consoleMessage.sourceId();
                String strR = android.support.v4.media.session.a.r(AbstractC0147y.h("JS: ", strMessage, " (", strSourceId, ":"), consoleMessage.lineNumber(), ")");
                if (!strR.contains("Application Cache")) {
                    int i = AbstractC2443oe.a[consoleMessage.messageLevel().ordinal()];
                    if (i == 1) {
                        com.google.android.gms.ads.internal.util.client.i.e(strR);
                    } else if (i == 2) {
                        com.google.android.gms.ads.internal.util.client.i.h(strR);
                    } else if (i == 3 || i == 4 || i != 5) {
                        com.google.android.gms.ads.internal.util.client.i.g(strR);
                    } else {
                        com.google.android.gms.ads.internal.util.client.i.d(strR);
                    }
                    break;
                } else {
                    break;
                }
                break;
        }
        return super.onConsoleMessage(consoleMessage);
    }

    @Override // android.webkit.WebChromeClient
    public boolean onCreateWindow(WebView webView, boolean z, boolean z2, Message message) {
        switch (this.a) {
            case 0:
                WebView.WebViewTransport webViewTransport = (WebView.WebViewTransport) message.obj;
                WebView webView2 = new WebView(webView.getContext());
                C1669Be c1669Be = ((C2743ve) this.b).a.n;
                if (c1669Be != null) {
                    webView2.setWebViewClient(c1669Be);
                }
                webViewTransport.setWebView(webView2);
                message.sendToTarget();
                return true;
            default:
                return super.onCreateWindow(webView, z, z2, message);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onExceededDatabaseQuota(String str, String str2, long j, long j2, long j3, WebStorage.QuotaUpdater quotaUpdater) {
        switch (this.a) {
            case 0:
                long j4 = 5242880 - j3;
                if (j4 > 0) {
                    if (j == 0) {
                        if (j2 > j4 || j2 > 1048576) {
                            j2 = 0;
                        }
                    } else if (j2 == 0) {
                        j2 = Math.min(Math.min(131072L, j4) + j, 1048576L);
                    } else {
                        if (j2 <= Math.min(1048576 - j, j4)) {
                            j += j2;
                        }
                        j2 = j;
                    }
                    quotaUpdater.updateQuota(j2);
                    break;
                } else {
                    quotaUpdater.updateQuota(j);
                    break;
                }
                break;
            default:
                super.onExceededDatabaseQuota(str, str2, j, j2, j3, quotaUpdater);
                break;
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onGeolocationPermissionsShowPrompt(String str, GeolocationPermissions.Callback callback) {
        switch (this.a) {
            case 0:
                if (callback != null) {
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    C2743ve c2743ve = (C2743ve) this.b;
                    boolean z = com.google.android.gms.ads.internal.util.F.b(c2743ve.getContext(), "android.permission.ACCESS_FINE_LOCATION") || com.google.android.gms.ads.internal.util.F.b(c2743ve.getContext(), "android.permission.ACCESS_COARSE_LOCATION");
                    C2601s7 c2601s7 = AbstractC2773w7.ed;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                        callback.invoke(str, false, true);
                    } else {
                        callback.invoke(str, z, true);
                    }
                    if (((Boolean) rVar.c.a(AbstractC2773w7.fd)).booleanValue()) {
                        com.google.android.gms.ads.internal.util.client.i.d("AdWebChromeClient.onGeolocationPermissionsShowPrompt()");
                        break;
                    }
                }
                break;
            default:
                super.onGeolocationPermissionsShowPrompt(str, callback);
                break;
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onHideCustomView() {
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.overlay.d dVarQ = ((C2743ve) this.b).a.Q();
                if (dVarQ != null) {
                    dVarQ.h();
                    break;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("Could not get ad overlay when hiding custom view.");
                    break;
                }
            default:
                super.onHideCustomView();
                break;
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsAlert(WebView webView, String str, String str2, JsResult jsResult) {
        switch (this.a) {
            case 0:
                return a(b(webView), "alert", str, str2, null, jsResult, null, false);
            default:
                return super.onJsAlert(webView, str, str2, jsResult);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsBeforeUnload(WebView webView, String str, String str2, JsResult jsResult) {
        switch (this.a) {
            case 0:
                return a(b(webView), "onBeforeUnload", str, str2, null, jsResult, null, false);
            default:
                return super.onJsBeforeUnload(webView, str, str2, jsResult);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsConfirm(WebView webView, String str, String str2, JsResult jsResult) {
        switch (this.a) {
            case 0:
                return a(b(webView), "confirm", str, str2, null, jsResult, null, false);
            default:
                return super.onJsConfirm(webView, str, str2, jsResult);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsPrompt(WebView webView, String str, String str2, String str3, JsPromptResult jsPromptResult) {
        switch (this.a) {
            case 0:
                return a(b(webView), "prompt", str, str2, str3, null, jsPromptResult, true);
            default:
                return super.onJsPrompt(webView, str, str2, str3, jsPromptResult);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onProgressChanged(WebView view, int i) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(view, "view");
                ProgressBar progressBar = ((C4607k) ((WebViewActivity) this.b).K()).d;
                Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                progressBar.setProgress(i);
                break;
            default:
                super.onProgressChanged(view, i);
                break;
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onShowCustomView(View view, int i, WebChromeClient.CustomViewCallback customViewCallback) {
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.overlay.d dVarQ = ((C2743ve) this.b).a.Q();
                if (dVarQ != null) {
                    Activity activity = dVarQ.b;
                    FrameLayout frameLayout = new FrameLayout(activity);
                    dVarQ.h = frameLayout;
                    frameLayout.setBackgroundColor(-16777216);
                    dVarQ.h.addView(view, -1, -1);
                    activity.setContentView(dVarQ.h);
                    dVarQ.r = true;
                    dVarQ.i = customViewCallback;
                    dVarQ.g = true;
                    dVarQ.e4(i);
                    break;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("Could not get ad overlay when showing custom view.");
                    customViewCallback.onCustomViewHidden();
                    break;
                }
            default:
                super.onShowCustomView(view, i, customViewCallback);
                break;
        }
    }

    public C2486pe(WebViewActivity webViewActivity) {
        this.b = webViewActivity;
    }

    @Override // android.webkit.WebChromeClient
    public void onShowCustomView(View view, WebChromeClient.CustomViewCallback customViewCallback) {
        switch (this.a) {
            case 0:
                onShowCustomView(view, -1, customViewCallback);
                break;
            default:
                super.onShowCustomView(view, customViewCallback);
                break;
        }
    }
}
