package com.pubmatic.sdk.common.browser;

import android.R;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.pubmatic.sdk.common.k;
import com.pubmatic.sdk.common.l;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class POBInternalBrowserActivity extends Activity {
    private static List<com.pubmatic.sdk.common.browser.a> a;
    private ImageView b;
    private ImageView c;
    private WebView d;
    private ProgressBar e;
    private int f;
    private AlertDialog g;
    private ViewGroup h;

    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            POBInternalBrowserActivity.this.finish();
        }
    }

    public class b implements View.OnClickListener {
        public b() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            POBInternalBrowserActivity.this.l();
        }
    }

    public class c implements View.OnClickListener {
        public c() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (POBInternalBrowserActivity.this.d != null) {
                POBInternalBrowserActivity.this.d.goForward();
            }
        }
    }

    public class d implements View.OnClickListener {
        public d() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (POBInternalBrowserActivity.this.d != null) {
                POBInternalBrowserActivity.this.d.reload();
            }
        }
    }

    public class e implements View.OnClickListener {
        public e() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            POBInternalBrowserActivity.this.j();
        }
    }

    public class f extends WebViewClient {
        private f() {
        }

        @Override // android.webkit.WebViewClient
        public void onPageFinished(WebView webView, String str) {
            if (POBInternalBrowserActivity.this.e != null) {
                POBInternalBrowserActivity.this.e.setVisibility(8);
            }
            if (POBInternalBrowserActivity.this.d != null) {
                if (POBInternalBrowserActivity.this.b != null) {
                    POBInternalBrowserActivity pOBInternalBrowserActivity = POBInternalBrowserActivity.this;
                    pOBInternalBrowserActivity.a(pOBInternalBrowserActivity.b, POBInternalBrowserActivity.this.d.canGoBack());
                }
                if (POBInternalBrowserActivity.this.c != null) {
                    POBInternalBrowserActivity pOBInternalBrowserActivity2 = POBInternalBrowserActivity.this;
                    pOBInternalBrowserActivity2.a(pOBInternalBrowserActivity2.c, POBInternalBrowserActivity.this.d.canGoForward());
                }
            }
        }

        @Override // android.webkit.WebViewClient
        public void onPageStarted(WebView webView, String str, Bitmap bitmap) {
            if (POBInternalBrowserActivity.this.e != null) {
                POBInternalBrowserActivity.this.e.setVisibility(0);
            }
            super.onPageStarted(webView, str, bitmap);
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedError(WebView webView, int i, String str, String str2) {
            ProgressBar unused = POBInternalBrowserActivity.this.e;
            super.onReceivedError(webView, i, str, str2);
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedSslError(WebView webView, SslErrorHandler sslErrorHandler, SslError sslError) {
            POBLog.warn("POBInternalBrowserActivity", "SSL error: %s", sslError);
            if (POBInternalBrowserActivity.this.e != null) {
                POBInternalBrowserActivity.this.e.setVisibility(8);
            }
            String str = "Connection to this site is not secure: " + POBInternalBrowserActivity.this.b(sslError.getPrimaryError());
            if (POBInternalBrowserActivity.this.isFinishing()) {
                POBLog.warn("POBInternalBrowserActivity", "Error showing ssl error dialog as activity is finishing!", new Object[0]);
                return;
            }
            if (POBInternalBrowserActivity.this.g != null) {
                if (POBInternalBrowserActivity.this.g.isShowing()) {
                    return;
                }
                POBInternalBrowserActivity.this.g.setMessage(str);
                POBInternalBrowserActivity.this.g.show();
                return;
            }
            AlertDialog.Builder builderBuild = com.pubmatic.sdk.common.utility.c.build(POBInternalBrowserActivity.this, "Warning!", str, new com.pubmatic.sdk.common.browser.b(this, sslErrorHandler));
            if (builderBuild != null) {
                try {
                    POBInternalBrowserActivity.this.g = builderBuild.create();
                    POBInternalBrowserActivity.this.g.show();
                } catch (Exception unused) {
                    POBLog.error("POBInternalBrowserActivity", "Error showing ssl error dialog.", new Object[0]);
                }
            }
        }

        @Override // android.webkit.WebViewClient
        public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
            POBInternalBrowserActivity.this.h();
            POBInternalBrowserActivity.this.finish();
            return true;
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView webView, String str) {
            return false;
        }

        public /* synthetic */ f(POBInternalBrowserActivity pOBInternalBrowserActivity, a aVar) {
            this();
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
            return com.pubmatic.sdk.common.utility.e.validateAndRedirect(POBInternalBrowserActivity.this, webResourceRequest.getUrl().toString());
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedError(WebView webView, WebResourceRequest webResourceRequest, WebResourceError webResourceError) {
            if (POBInternalBrowserActivity.this.e != null) {
                POBInternalBrowserActivity.this.e.setVisibility(8);
            }
            super.onReceivedError(webView, webResourceRequest, webResourceError);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NonNull
    public String b(int i) {
        return i != 0 ? i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "SSL Error." : "Certificate Invalid." : "Invalid Date." : "Untrusted Certificate." : "Domain Name Mismatched." : "Certificate Expired." : "Certificate Invalid.";
    }

    private void i() {
        List<com.pubmatic.sdk.common.browser.a> list = a;
        if (list != null) {
            for (com.pubmatic.sdk.common.browser.a aVar : list) {
                if (this.f == aVar.hashCode()) {
                    aVar.onBrowserDismiss();
                    a(aVar);
                    return;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void j() {
        List<com.pubmatic.sdk.common.browser.a> list = a;
        if (list != null) {
            for (com.pubmatic.sdk.common.browser.a aVar : list) {
                if (this.d != null && aVar.hashCode() == this.f) {
                    String url = this.d.getUrl();
                    if (url != null) {
                        aVar.onExternalBrowserClick(url);
                    } else {
                        POBLog.debug("POBInternalBrowserActivity", "Can't open external browser as url is not available.", new Object[0]);
                    }
                }
            }
        }
    }

    private void k() {
        List<com.pubmatic.sdk.common.browser.a> list = a;
        if (list != null) {
            for (com.pubmatic.sdk.common.browser.a aVar : list) {
                if (this.f == aVar.hashCode()) {
                    aVar.onBrowserStart();
                    return;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void l() {
        WebView webView = this.d;
        if (webView == null || !webView.canGoBack()) {
            super.onBackPressed();
        } else {
            this.d.goBack();
        }
    }

    public static void startNewActivity(@NonNull Context context, @NonNull String str, @NonNull com.pubmatic.sdk.common.browser.a aVar) {
        if (a == null) {
            a = new ArrayList();
        }
        a.add(aVar);
        Intent intent = new Intent(context, (Class<?>) POBInternalBrowserActivity.class);
        intent.addFlags(268435456);
        intent.putExtra(DTBMetricsConfiguration.APSMETRICS_URL, str);
        intent.putExtra("listener_hash_code", aVar.hashCode());
        context.startActivity(intent);
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        l();
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(c());
        this.h = (ViewGroup) findViewById(R.id.content);
        this.f = getIntent().getIntExtra("listener_hash_code", 0);
        a(getIntent().getStringExtra(DTBMetricsConfiguration.APSMETRICS_URL));
        k();
    }

    @Override // android.app.Activity
    public void onDestroy() {
        POBLog.debug("POBInternalBrowserActivity", "Activity on destroy called.", new Object[0]);
        h();
        AlertDialog alertDialog = this.g;
        if (alertDialog != null) {
            alertDialog.dismiss();
            this.g = null;
        }
        super.onDestroy();
        i();
    }

    @NonNull
    private RelativeLayout c() {
        RelativeLayout relativeLayout = new RelativeLayout(this);
        relativeLayout.setBackgroundColor(-1);
        a(relativeLayout);
        return relativeLayout;
    }

    @NonNull
    private ImageView d() {
        ImageView imageViewA = a(k.pob_ic_action_web_site);
        imageViewA.setOnClickListener(new e());
        return imageViewA;
    }

    private ImageView e() {
        ImageView imageViewA = a(k.pob_ic_action_forward);
        this.c = imageViewA;
        a(imageViewA, false);
        this.c.setOnClickListener(new c());
        return this.c;
    }

    @NonNull
    private ImageView f() {
        ImageView imageViewA = a(k.pob_ic_action_refresh);
        imageViewA.setOnClickListener(new d());
        return imageViewA;
    }

    @SuppressLint({"SetJavaScriptEnabled"})
    private WebView g() {
        com.pubmatic.sdk.common.view.c cVarCreateInstance = com.pubmatic.sdk.common.view.c.createInstance(o.resolveWebViewContext(this));
        if (cVarCreateInstance != null) {
            WebSettings settings = cVarCreateInstance.getSettings();
            settings.setJavaScriptEnabled(true);
            settings.setLoadWithOverviewMode(true);
            settings.setUseWideViewPort(true);
            settings.setDomStorageEnabled(true);
            cVarCreateInstance.setWebViewClient(new f(this, null));
        }
        return cVarCreateInstance;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void h() {
        ViewGroup viewGroup = this.h;
        if (viewGroup != null) {
            viewGroup.removeAllViews();
            this.h = null;
        }
        WebView webView = this.d;
        if (webView != null) {
            webView.setWebViewClient(null);
            this.d.destroy();
            this.d = null;
        }
    }

    @NonNull
    private ImageView b() {
        ImageView imageViewA = a(k.pob_ic_action_cancel);
        imageViewA.setOnClickListener(new a());
        return imageViewA;
    }

    private void a(@NonNull com.pubmatic.sdk.common.browser.a aVar) {
        List<com.pubmatic.sdk.common.browser.a> list = a;
        if (list != null) {
            list.remove(aVar);
            if (a.isEmpty()) {
                a = null;
            }
        }
    }

    private void a(String str) {
        if (this.d != null && !o.isNullOrEmpty(str)) {
            POBLog.debug("POBInternalBrowserActivity", "Loading url in internal browser : %s", str);
            this.d.loadUrl(str);
        } else {
            POBLog.warn("POBInternalBrowserActivity", "Unable to open internal browser : %s", "Invalid url");
        }
    }

    private void a(RelativeLayout relativeLayout) {
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-1, o.convertDpToPixel(40));
        layoutParams.addRule(12);
        LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setId(l.pob_dialog_id);
        linearLayout.setBackgroundColor(-12303292);
        linearLayout.setOrientation(0);
        linearLayout.setVerticalGravity(16);
        relativeLayout.addView(linearLayout, layoutParams);
        LinearLayout.LayoutParams layoutParams2 = new LinearLayout.LayoutParams(-1, -1, 1.0f);
        layoutParams2.setMargins(2, 4, 2, 2);
        linearLayout.addView(b(), layoutParams2);
        linearLayout.addView(a(), layoutParams2);
        linearLayout.addView(e(), layoutParams2);
        linearLayout.addView(f(), layoutParams2);
        linearLayout.addView(d(), layoutParams2);
        RelativeLayout.LayoutParams layoutParams3 = new RelativeLayout.LayoutParams(-1, 0);
        layoutParams3.addRule(10);
        layoutParams3.addRule(2, linearLayout.getId());
        WebView webViewG = g();
        this.d = webViewG;
        if (webViewG != null) {
            relativeLayout.addView(webViewG, layoutParams3);
            RelativeLayout.LayoutParams layoutParams4 = new RelativeLayout.LayoutParams(-2, -2);
            layoutParams4.addRule(13);
            ProgressBar progressBar = new ProgressBar(this, null, R.attr.progressBarStyle);
            this.e = progressBar;
            relativeLayout.addView(progressBar, layoutParams4);
            return;
        }
        finish();
    }

    @NonNull
    private ImageView a() {
        ImageView imageViewA = a(k.pob_ic_action_back);
        this.b = imageViewA;
        a(imageViewA, false);
        this.b.setOnClickListener(new b());
        return this.b;
    }

    @NonNull
    private ImageView a(int i) {
        ImageView imageView = new ImageView(this);
        ImageView.ScaleType scaleType = ImageView.ScaleType.FIT_CENTER;
        imageView.setImageResource(i);
        imageView.setBackgroundColor(getResources().getColor(R.color.background_dark, getTheme()));
        imageView.setScaleType(scaleType);
        return imageView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull ImageView imageView, boolean z) {
        if (z) {
            imageView.setEnabled(true);
            imageView.setImageAlpha(255);
        } else {
            imageView.setEnabled(false);
            imageView.setImageAlpha(160);
        }
    }
}
