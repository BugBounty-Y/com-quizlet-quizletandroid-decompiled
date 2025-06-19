package com.quizlet.quizletandroid.ui.webpages;

import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Toast;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.compose.animation.d0;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.recyclerview.widget.C1372j;
import com.bumptech.glide.c;
import com.google.android.gms.internal.ads.C2486pe;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.ads.ui.activity.d;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4607k;
import com.quizlet.quizletandroid.managers.deeplinks.h;
import com.quizlet.ui.webview.QuizletWebView;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.u;
import okhttp3.s;

@Metadata
/* loaded from: classes3.dex */
public class WebViewActivity extends d {
    public static final String u;
    public com.quizlet.db.token.a q;
    public com.quizlet.features.consent.onetrust.d r;
    public com.quizlet.data.repository.login.a s;
    public h t;

    static {
        Intrinsics.checkNotNullExpressionValue("WebViewActivity", "getSimpleName(...)");
        u = "WebViewActivity";
    }

    public WebViewActivity() {
        super(13);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return u;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_web_view, (ViewGroup) null, false);
        int i = R.id.appBarLayout;
        AppBarLayout appBarLayout = (AppBarLayout) AbstractC3375o2.c(R.id.appBarLayout, viewInflate);
        if (appBarLayout != null) {
            i = R.id.bottomButton;
            QButton qButton = (QButton) AbstractC3375o2.c(R.id.bottomButton, viewInflate);
            if (qButton != null) {
                LinearLayout linearLayout = (LinearLayout) viewInflate;
                i = R.id.progressBar;
                ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.progressBar, viewInflate);
                if (progressBar != null) {
                    i = R.id.toolbar;
                    Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, viewInflate);
                    if (toolbar != null) {
                        i = R.id.web_view;
                        QuizletWebView quizletWebView = (QuizletWebView) AbstractC3375o2.c(R.id.web_view, viewInflate);
                        if (quizletWebView != null) {
                            C4607k c4607k = new C4607k(linearLayout, appBarLayout, qButton, progressBar, toolbar, quizletWebView);
                            Intrinsics.checkNotNullExpressionValue(c4607k, "inflate(...)");
                            return c4607k;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final QuizletWebView b0() {
        QuizletWebView webView = ((C4607k) K()).f;
        Intrinsics.checkNotNullExpressionValue(webView, "webView");
        return webView;
    }

    public final String c0() {
        String stringExtra = getIntent().getStringExtra("extra.url");
        s sVarD = null;
        if (stringExtra == null) {
            return null;
        }
        u uVar = com.quizlet.themes.extensions.a.a;
        Intrinsics.checkNotNullParameter(this, "<this>");
        getTheme().resolveAttribute(R.attr.IsNightTheme, com.quizlet.themes.extensions.a.b(), true);
        String str = com.quizlet.themes.extensions.a.b().data != 0 ? "night" : "default";
        Intrinsics.checkNotNullParameter(stringExtra, "<this>");
        try {
            Intrinsics.checkNotNullParameter(stringExtra, "<this>");
            C1372j c1372j = new C1372j();
            c1372j.l(null, stringExtra);
            sVarD = c1372j.d();
        } catch (IllegalArgumentException unused) {
        }
        if (sVarD != null) {
            C1372j c1372jF = sVarD.f();
            c1372jF.c("__injectedColorTheme", str);
            String str2 = c1372jF.d().i;
            if (str2 != null) {
                return str2;
            }
        }
        return stringExtra;
    }

    public final void d0(Drawable drawable) {
        v(((C4607k) K()).e);
        c cVarR = r();
        if (cVarR != null) {
            if (drawable != null) {
                cVarR.v(drawable);
                cVarR.u(false);
                cVarR.s(true);
                cVarR.t();
            }
            String stringExtra = getIntent().getStringExtra("extra.mTitle");
            if (stringExtra == null || stringExtra.length() <= 0) {
                return;
            }
            cVarR.u(true);
            cVarR.A(stringExtra);
        }
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        C4607k c4607k = (C4607k) K();
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 22);
        WeakHashMap weakHashMap = V.a;
        L.m(c4607k.a, bVar);
        String strC0 = c0();
        if (strC0 == null || StringsKt.O(strC0)) {
            Toast.makeText(this, R.string.web_browser_disabled_error, 1).show();
            timber.log.c.a.d("Missing extra: (%s)", "extra.url");
            finish();
        }
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public final boolean onKeyDown(int i, KeyEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (i != 4) {
            return super.onKeyDown(i, event);
        }
        if (b0().canGoBack()) {
            b0().goBack();
            return true;
        }
        finish();
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public void onPostCreate(Bundle bundle) {
        List<String> pathSegments;
        Set<String> setKeySet;
        super.onPostCreate(bundle);
        d0(getDrawable(R.drawable.ic_sys_close_x));
        b0().setQWebViewClient(new com.facebook.internal.L(this, 6));
        b0().setWebChromeClient(new C2486pe(this));
        WebSettings settings = b0().getSettings();
        settings.setLoadsImagesAutomatically(true);
        settings.setJavaScriptEnabled(true);
        String userAgentString = settings.getUserAgentString();
        Intrinsics.checkNotNullParameter("9.34.3", "versionName");
        settings.setUserAgentString(userAgentString + d0.s(new Object[]{"9.34.3"}, 1, "[QWebView P/android;V/%s]", "format(...)"));
        Uri uri = Uri.parse(c0());
        Intrinsics.d(uri);
        if (!a.d(uri)) {
            timber.log.c.a.g("URL is not on an allowed domain, handling externally: %s", c0());
            a.a.a(this, uri);
            finish();
            return;
        }
        timber.log.c.a.g("Loading URL in WebView: %s", c0());
        Bundle bundleExtra = getIntent().getBundleExtra("extra.request.params");
        String strC0 = c0();
        if (strC0 != null) {
            QuizletWebView quizletWebViewB0 = b0();
            com.quizlet.db.token.a aVar = this.q;
            if (aVar == null) {
                Intrinsics.m("mAccessTokenProvider");
                throw null;
            }
            String strA = aVar.a();
            HashMap map = new HashMap();
            if (bundleExtra != null && (setKeySet = bundleExtra.keySet()) != null) {
                for (String str : setKeySet) {
                    map.put(str, bundleExtra.getString(str));
                }
            }
            if (strA != null && (pathSegments = uri.getPathSegments()) != null && !pathSegments.isEmpty()) {
                Iterator<T> it2 = pathSegments.iterator();
                while (true) {
                    if (it2.hasNext()) {
                        if (Intrinsics.b((String) it2.next(), "oauthweb")) {
                            map.put("Authorization", "Bearer ".concat(strA));
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            quizletWebViewB0.loadUrl(strC0, map);
        }
    }
}
