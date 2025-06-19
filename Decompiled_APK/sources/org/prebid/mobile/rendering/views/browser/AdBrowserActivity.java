package org.prebid.mobile.rendering.views.browser;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.Window;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.MediaController;
import android.widget.RelativeLayout;
import android.widget.TableRow;
import android.widget.VideoView;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.utils.broadcast.local.BaseLocalBroadcastReceiver;
import org.prebid.mobile.rendering.utils.helpers.ExternalViewerUtils;

@SuppressLint({"NewApi"})
/* loaded from: classes3.dex */
public final class AdBrowserActivity extends Activity {
    public WebView a;
    public VideoView b;
    public BrowserControls c;
    public boolean d;
    public boolean e;
    public int f;
    public String g;

    /* renamed from: org.prebid.mobile.rendering.views.browser.AdBrowserActivity$1, reason: invalid class name */
    class AnonymousClass1 implements BrowserControlsEventsListener {
        public AnonymousClass1() {
        }
    }

    @Override // android.app.Activity
    public final void onBackPressed() {
        if (this.d) {
            super.onBackPressed();
        }
    }

    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Window window = getWindow();
        window.setBackgroundDrawable(new ColorDrawable(-1));
        window.setFlags(16777216, 16777216);
        window.setSoftInputMode(6);
        Bundle extras = getIntent().getExtras();
        RelativeLayout.LayoutParams layoutParams = null;
        if (extras != null) {
            this.g = extras.getString("EXTRA_URL", null);
            this.e = extras.getBoolean("EXTRA_SHOULD_FIRE_EVENTS", true);
            this.d = extras.getBoolean("EXTRA_IS_VIDEO", false);
            this.f = extras.getInt("EXTRA_BROADCAST_ID", -1);
        }
        if (this.d) {
            this.b = new VideoView(this);
            RelativeLayout relativeLayout = new RelativeLayout(this);
            RelativeLayout.LayoutParams layoutParams2 = new RelativeLayout.LayoutParams(-1, -1);
            layoutParams2.addRule(13);
            relativeLayout.addView(this.b, layoutParams2);
            setContentView(relativeLayout);
            this.b.setMediaController(new MediaController(this));
            this.b.setVideoURI(Uri.parse(this.g));
            this.b.start();
            return;
        }
        AnonymousClass1 anonymousClass1 = new AnonymousClass1();
        final BrowserControls browserControls = new BrowserControls(this);
        browserControls.h = new Handler(Looper.getMainLooper());
        browserControls.i = anonymousClass1;
        if (browserControls.getContext() != null) {
            TableRow tableRow = new TableRow(browserControls.getContext());
            browserControls.f = new LinearLayout(browserControls.getContext());
            browserControls.g = new LinearLayout(browserControls.getContext());
            browserControls.f.setVisibility(8);
            browserControls.g.setGravity(5);
            browserControls.setBackgroundColor(BrowserControls.j);
            Button button = new Button(browserControls.getContext());
            browserControls.a = button;
            button.setContentDescription("close");
            BrowserControls.a(browserControls.a);
            browserControls.a.setBackgroundResource(2131231743);
            Button button2 = new Button(browserControls.getContext());
            browserControls.b = button2;
            button2.setContentDescription("back");
            BrowserControls.a(browserControls.b);
            browserControls.b.setBackgroundResource(2131231742);
            Button button3 = new Button(browserControls.getContext());
            browserControls.c = button3;
            button3.setContentDescription("forth");
            BrowserControls.a(browserControls.c);
            browserControls.c.setBackgroundResource(2131231746);
            Button button4 = new Button(browserControls.getContext());
            browserControls.d = button4;
            button4.setContentDescription("refresh");
            BrowserControls.a(browserControls.d);
            browserControls.d.setBackgroundResource(2131231749);
            Button button5 = new Button(browserControls.getContext());
            browserControls.e = button5;
            button5.setContentDescription("openInExternalBrowser");
            BrowserControls.a(browserControls.e);
            browserControls.e.setBackgroundResource(2131231748);
            final int i = 0;
            browserControls.a.setOnClickListener(new View.OnClickListener() { // from class: org.prebid.mobile.rendering.views.browser.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    WebView webView;
                    BrowserControls browserControls2 = browserControls;
                    switch (i) {
                        case 0:
                            BrowserControlsEventsListener browserControlsEventsListener = browserControls2.i;
                            if (browserControlsEventsListener != null) {
                                AdBrowserActivity adBrowserActivity = AdBrowserActivity.this;
                                adBrowserActivity.finish();
                                if (adBrowserActivity.e) {
                                    Context applicationContext = adBrowserActivity.getApplicationContext();
                                    long j = adBrowserActivity.f;
                                    int i2 = BaseLocalBroadcastReceiver.a;
                                    Intent intent = new Intent("org.prebid.mobile.rendering.browser.close");
                                    intent.putExtra("BROADCAST_IDENTIFIER_KEY", j);
                                    androidx.localbroadcastmanager.content.b.a(applicationContext.getApplicationContext()).c(intent);
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Close button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 1:
                            BrowserControlsEventsListener browserControlsEventsListener2 = browserControls2.i;
                            if (browserControlsEventsListener2 != null) {
                                WebView webView2 = AdBrowserActivity.this.a;
                                if (webView2 != null) {
                                    webView2.goBack();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Back button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 2:
                            BrowserControlsEventsListener browserControlsEventsListener3 = browserControls2.i;
                            if (browserControlsEventsListener3 != null) {
                                WebView webView3 = AdBrowserActivity.this.a;
                                if (webView3 != null) {
                                    webView3.goForward();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Forward button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 3:
                            BrowserControlsEventsListener browserControlsEventsListener4 = browserControls2.i;
                            if (browserControlsEventsListener4 != null) {
                                WebView webView4 = AdBrowserActivity.this.a;
                                if (webView4 != null) {
                                    webView4.reload();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Refresh button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        default:
                            BrowserControlsEventsListener browserControlsEventsListener5 = browserControls2.i;
                            String url = null;
                            if (browserControlsEventsListener5 != null && (webView = AdBrowserActivity.this.a) != null) {
                                url = webView.getUrl();
                            }
                            if (url == null) {
                                LogUtil.b("BrowserControls", "Open external link failed. url is null");
                                break;
                            } else {
                                Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse(url));
                                intent2.addFlags(268435456);
                                try {
                                    ExternalViewerUtils.c(browserControls2.getContext(), intent2);
                                    break;
                                } catch (Exception e) {
                                    StringBuilder sbY = android.support.v4.media.session.a.y("Could not handle intent: ", url, " : ");
                                    sbY.append(Log.getStackTraceString(e));
                                    LogUtil.b("BrowserControls", sbY.toString());
                                }
                            }
                            break;
                    }
                }
            });
            final int i2 = 1;
            browserControls.b.setOnClickListener(new View.OnClickListener() { // from class: org.prebid.mobile.rendering.views.browser.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    WebView webView;
                    BrowserControls browserControls2 = browserControls;
                    switch (i2) {
                        case 0:
                            BrowserControlsEventsListener browserControlsEventsListener = browserControls2.i;
                            if (browserControlsEventsListener != null) {
                                AdBrowserActivity adBrowserActivity = AdBrowserActivity.this;
                                adBrowserActivity.finish();
                                if (adBrowserActivity.e) {
                                    Context applicationContext = adBrowserActivity.getApplicationContext();
                                    long j = adBrowserActivity.f;
                                    int i22 = BaseLocalBroadcastReceiver.a;
                                    Intent intent = new Intent("org.prebid.mobile.rendering.browser.close");
                                    intent.putExtra("BROADCAST_IDENTIFIER_KEY", j);
                                    androidx.localbroadcastmanager.content.b.a(applicationContext.getApplicationContext()).c(intent);
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Close button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 1:
                            BrowserControlsEventsListener browserControlsEventsListener2 = browserControls2.i;
                            if (browserControlsEventsListener2 != null) {
                                WebView webView2 = AdBrowserActivity.this.a;
                                if (webView2 != null) {
                                    webView2.goBack();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Back button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 2:
                            BrowserControlsEventsListener browserControlsEventsListener3 = browserControls2.i;
                            if (browserControlsEventsListener3 != null) {
                                WebView webView3 = AdBrowserActivity.this.a;
                                if (webView3 != null) {
                                    webView3.goForward();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Forward button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 3:
                            BrowserControlsEventsListener browserControlsEventsListener4 = browserControls2.i;
                            if (browserControlsEventsListener4 != null) {
                                WebView webView4 = AdBrowserActivity.this.a;
                                if (webView4 != null) {
                                    webView4.reload();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Refresh button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        default:
                            BrowserControlsEventsListener browserControlsEventsListener5 = browserControls2.i;
                            String url = null;
                            if (browserControlsEventsListener5 != null && (webView = AdBrowserActivity.this.a) != null) {
                                url = webView.getUrl();
                            }
                            if (url == null) {
                                LogUtil.b("BrowserControls", "Open external link failed. url is null");
                                break;
                            } else {
                                Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse(url));
                                intent2.addFlags(268435456);
                                try {
                                    ExternalViewerUtils.c(browserControls2.getContext(), intent2);
                                    break;
                                } catch (Exception e) {
                                    StringBuilder sbY = android.support.v4.media.session.a.y("Could not handle intent: ", url, " : ");
                                    sbY.append(Log.getStackTraceString(e));
                                    LogUtil.b("BrowserControls", sbY.toString());
                                }
                            }
                            break;
                    }
                }
            });
            final int i3 = 2;
            browserControls.c.setOnClickListener(new View.OnClickListener() { // from class: org.prebid.mobile.rendering.views.browser.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    WebView webView;
                    BrowserControls browserControls2 = browserControls;
                    switch (i3) {
                        case 0:
                            BrowserControlsEventsListener browserControlsEventsListener = browserControls2.i;
                            if (browserControlsEventsListener != null) {
                                AdBrowserActivity adBrowserActivity = AdBrowserActivity.this;
                                adBrowserActivity.finish();
                                if (adBrowserActivity.e) {
                                    Context applicationContext = adBrowserActivity.getApplicationContext();
                                    long j = adBrowserActivity.f;
                                    int i22 = BaseLocalBroadcastReceiver.a;
                                    Intent intent = new Intent("org.prebid.mobile.rendering.browser.close");
                                    intent.putExtra("BROADCAST_IDENTIFIER_KEY", j);
                                    androidx.localbroadcastmanager.content.b.a(applicationContext.getApplicationContext()).c(intent);
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Close button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 1:
                            BrowserControlsEventsListener browserControlsEventsListener2 = browserControls2.i;
                            if (browserControlsEventsListener2 != null) {
                                WebView webView2 = AdBrowserActivity.this.a;
                                if (webView2 != null) {
                                    webView2.goBack();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Back button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 2:
                            BrowserControlsEventsListener browserControlsEventsListener3 = browserControls2.i;
                            if (browserControlsEventsListener3 != null) {
                                WebView webView3 = AdBrowserActivity.this.a;
                                if (webView3 != null) {
                                    webView3.goForward();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Forward button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 3:
                            BrowserControlsEventsListener browserControlsEventsListener4 = browserControls2.i;
                            if (browserControlsEventsListener4 != null) {
                                WebView webView4 = AdBrowserActivity.this.a;
                                if (webView4 != null) {
                                    webView4.reload();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Refresh button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        default:
                            BrowserControlsEventsListener browserControlsEventsListener5 = browserControls2.i;
                            String url = null;
                            if (browserControlsEventsListener5 != null && (webView = AdBrowserActivity.this.a) != null) {
                                url = webView.getUrl();
                            }
                            if (url == null) {
                                LogUtil.b("BrowserControls", "Open external link failed. url is null");
                                break;
                            } else {
                                Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse(url));
                                intent2.addFlags(268435456);
                                try {
                                    ExternalViewerUtils.c(browserControls2.getContext(), intent2);
                                    break;
                                } catch (Exception e) {
                                    StringBuilder sbY = android.support.v4.media.session.a.y("Could not handle intent: ", url, " : ");
                                    sbY.append(Log.getStackTraceString(e));
                                    LogUtil.b("BrowserControls", sbY.toString());
                                }
                            }
                            break;
                    }
                }
            });
            final int i4 = 3;
            browserControls.d.setOnClickListener(new View.OnClickListener() { // from class: org.prebid.mobile.rendering.views.browser.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    WebView webView;
                    BrowserControls browserControls2 = browserControls;
                    switch (i4) {
                        case 0:
                            BrowserControlsEventsListener browserControlsEventsListener = browserControls2.i;
                            if (browserControlsEventsListener != null) {
                                AdBrowserActivity adBrowserActivity = AdBrowserActivity.this;
                                adBrowserActivity.finish();
                                if (adBrowserActivity.e) {
                                    Context applicationContext = adBrowserActivity.getApplicationContext();
                                    long j = adBrowserActivity.f;
                                    int i22 = BaseLocalBroadcastReceiver.a;
                                    Intent intent = new Intent("org.prebid.mobile.rendering.browser.close");
                                    intent.putExtra("BROADCAST_IDENTIFIER_KEY", j);
                                    androidx.localbroadcastmanager.content.b.a(applicationContext.getApplicationContext()).c(intent);
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Close button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 1:
                            BrowserControlsEventsListener browserControlsEventsListener2 = browserControls2.i;
                            if (browserControlsEventsListener2 != null) {
                                WebView webView2 = AdBrowserActivity.this.a;
                                if (webView2 != null) {
                                    webView2.goBack();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Back button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 2:
                            BrowserControlsEventsListener browserControlsEventsListener3 = browserControls2.i;
                            if (browserControlsEventsListener3 != null) {
                                WebView webView3 = AdBrowserActivity.this.a;
                                if (webView3 != null) {
                                    webView3.goForward();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Forward button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 3:
                            BrowserControlsEventsListener browserControlsEventsListener4 = browserControls2.i;
                            if (browserControlsEventsListener4 != null) {
                                WebView webView4 = AdBrowserActivity.this.a;
                                if (webView4 != null) {
                                    webView4.reload();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Refresh button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        default:
                            BrowserControlsEventsListener browserControlsEventsListener5 = browserControls2.i;
                            String url = null;
                            if (browserControlsEventsListener5 != null && (webView = AdBrowserActivity.this.a) != null) {
                                url = webView.getUrl();
                            }
                            if (url == null) {
                                LogUtil.b("BrowserControls", "Open external link failed. url is null");
                                break;
                            } else {
                                Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse(url));
                                intent2.addFlags(268435456);
                                try {
                                    ExternalViewerUtils.c(browserControls2.getContext(), intent2);
                                    break;
                                } catch (Exception e) {
                                    StringBuilder sbY = android.support.v4.media.session.a.y("Could not handle intent: ", url, " : ");
                                    sbY.append(Log.getStackTraceString(e));
                                    LogUtil.b("BrowserControls", sbY.toString());
                                }
                            }
                            break;
                    }
                }
            });
            final int i5 = 4;
            browserControls.e.setOnClickListener(new View.OnClickListener() { // from class: org.prebid.mobile.rendering.views.browser.b
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    WebView webView;
                    BrowserControls browserControls2 = browserControls;
                    switch (i5) {
                        case 0:
                            BrowserControlsEventsListener browserControlsEventsListener = browserControls2.i;
                            if (browserControlsEventsListener != null) {
                                AdBrowserActivity adBrowserActivity = AdBrowserActivity.this;
                                adBrowserActivity.finish();
                                if (adBrowserActivity.e) {
                                    Context applicationContext = adBrowserActivity.getApplicationContext();
                                    long j = adBrowserActivity.f;
                                    int i22 = BaseLocalBroadcastReceiver.a;
                                    Intent intent = new Intent("org.prebid.mobile.rendering.browser.close");
                                    intent.putExtra("BROADCAST_IDENTIFIER_KEY", j);
                                    androidx.localbroadcastmanager.content.b.a(applicationContext.getApplicationContext()).c(intent);
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Close button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 1:
                            BrowserControlsEventsListener browserControlsEventsListener2 = browserControls2.i;
                            if (browserControlsEventsListener2 != null) {
                                WebView webView2 = AdBrowserActivity.this.a;
                                if (webView2 != null) {
                                    webView2.goBack();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Back button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 2:
                            BrowserControlsEventsListener browserControlsEventsListener3 = browserControls2.i;
                            if (browserControlsEventsListener3 != null) {
                                WebView webView3 = AdBrowserActivity.this.a;
                                if (webView3 != null) {
                                    webView3.goForward();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Forward button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        case 3:
                            BrowserControlsEventsListener browserControlsEventsListener4 = browserControls2.i;
                            if (browserControlsEventsListener4 != null) {
                                WebView webView4 = AdBrowserActivity.this.a;
                                if (webView4 != null) {
                                    webView4.reload();
                                    break;
                                }
                            } else {
                                LogUtil.b("BrowserControls", "Refresh button click failed: browserControlsEventsListener is null");
                                break;
                            }
                            break;
                        default:
                            BrowserControlsEventsListener browserControlsEventsListener5 = browserControls2.i;
                            String url = null;
                            if (browserControlsEventsListener5 != null && (webView = AdBrowserActivity.this.a) != null) {
                                url = webView.getUrl();
                            }
                            if (url == null) {
                                LogUtil.b("BrowserControls", "Open external link failed. url is null");
                                break;
                            } else {
                                Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse(url));
                                intent2.addFlags(268435456);
                                try {
                                    ExternalViewerUtils.c(browserControls2.getContext(), intent2);
                                    break;
                                } catch (Exception e) {
                                    StringBuilder sbY = android.support.v4.media.session.a.y("Could not handle intent: ", url, " : ");
                                    sbY.append(Log.getStackTraceString(e));
                                    LogUtil.b("BrowserControls", sbY.toString());
                                }
                            }
                            break;
                    }
                }
            });
            browserControls.f.addView(browserControls.b);
            browserControls.f.addView(browserControls.c);
            browserControls.f.addView(browserControls.d);
            browserControls.f.addView(browserControls.e);
            browserControls.g.addView(browserControls.a);
            tableRow.addView(browserControls.f, new TableRow.LayoutParams(-1, -1, 3.0f));
            tableRow.addView(browserControls.g, new TableRow.LayoutParams(-1, -1, 5.0f));
            browserControls.addView(tableRow);
        }
        browserControls.setId(235799);
        this.c = browserControls;
        RelativeLayout relativeLayout2 = new RelativeLayout(this);
        RelativeLayout.LayoutParams layoutParams3 = new RelativeLayout.LayoutParams(-1, -1);
        if (!TextUtils.isEmpty(this.g)) {
            WebView webView = new WebView(this);
            this.a = webView;
            webView.getSettings().setJavaScriptEnabled(true);
            this.a.getSettings().setJavaScriptCanOpenWindowsAutomatically(false);
            this.a.getSettings().setPluginState(WebSettings.PluginState.OFF);
            this.a.setHorizontalScrollBarEnabled(false);
            this.a.setVerticalScrollBarEnabled(false);
            this.a.getSettings().setCacheMode(2);
            this.a.getSettings().setBuiltInZoomControls(true);
            this.a.getSettings().setDisplayZoomControls(false);
            this.a.getSettings().setLoadWithOverviewMode(true);
            this.a.getSettings().setUseWideViewPort(true);
            WebView webView2 = this.a;
            AdBrowserActivityWebViewClient adBrowserActivityWebViewClient = new AdBrowserActivityWebViewClient();
            adBrowserActivityWebViewClient.a = this;
            webView2.setWebViewClient(adBrowserActivityWebViewClient);
            this.a.loadUrl(this.g);
            layoutParams = new RelativeLayout.LayoutParams(-1, -2);
            BrowserControls browserControls2 = this.c;
            if (browserControls2 != null) {
                browserControls2.f.setVisibility(0);
            }
            layoutParams3.addRule(3, 235799);
        }
        WebView webView3 = this.a;
        if (webView3 != null) {
            relativeLayout2.addView(webView3, layoutParams3);
        }
        BrowserControls browserControls3 = this.c;
        if (browserControls3 != null) {
            relativeLayout2.addView(browserControls3, layoutParams);
        }
        setContentView(relativeLayout2);
    }

    @Override // android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        WebView webView = this.a;
        if (webView != null) {
            webView.destroy();
        }
        VideoView videoView = this.b;
        if (videoView != null) {
            videoView.suspend();
        }
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public final boolean onKeyDown(int i, KeyEvent keyEvent) {
        if (i == 4) {
            WebView webView = this.a;
            if (webView != null) {
                webView.goBack();
            }
            finish();
        }
        return super.onKeyDown(i, keyEvent);
    }

    @Override // android.app.Activity
    public final void onPause() {
        super.onPause();
        VideoView videoView = this.b;
        if (videoView != null) {
            videoView.suspend();
        }
    }

    @Override // android.app.Activity
    public final void onResume() {
        super.onResume();
        VideoView videoView = this.b;
        if (videoView != null) {
            videoView.resume();
        }
    }
}
