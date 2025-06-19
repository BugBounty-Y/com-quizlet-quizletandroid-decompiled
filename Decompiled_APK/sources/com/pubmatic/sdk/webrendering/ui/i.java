package com.pubmatic.sdk.webrendering.ui;

import android.annotation.SuppressLint;
import android.os.Trace;
import android.view.MotionEvent;
import android.view.View;
import android.webkit.WebView;
import androidx.annotation.NonNull;
import androidx.compose.animation.d0;
import java.nio.charset.StandardCharsets;
import java.util.Formatter;
import java.util.IllegalFormatException;
import java.util.Locale;

/* loaded from: classes2.dex */
public class i implements j {
    private com.pubmatic.sdk.common.ui.e a;
    private com.pubmatic.sdk.common.view.c b;
    private boolean c;

    @NonNull
    private final Formatter d;
    private long e = 15;
    private com.pubmatic.sdk.common.utility.l f;

    public class a implements com.pubmatic.sdk.common.utility.k {
        public a() {
        }

        @Override // com.pubmatic.sdk.common.utility.k
        public void onTimeout() {
            i iVar = i.this;
            iVar.notifyError(new com.pubmatic.sdk.common.h(1009, d0.o(iVar.e, "Unable to render creative within ", " seconds.")));
        }
    }

    public class b implements Runnable {
        public b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            i.this.invalidateWebView();
        }
    }

    public class c implements View.OnTouchListener {
        public c() {
        }

        @Override // android.view.View.OnTouchListener
        @SuppressLint({"ClickableViewAccessibility"})
        public boolean onTouch(View view, MotionEvent motionEvent) {
            int action = motionEvent.getAction();
            if (action != 0 && action != 1) {
                return false;
            }
            i.this.c = true;
            return false;
        }
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public i(@NonNull com.pubmatic.sdk.common.view.c cVar, @NonNull l lVar) {
        this.b = cVar;
        cVar.setWebViewClient(lVar);
        this.b.setOnTouchListener(new c());
        lVar.setHTMLClientListener(this);
        this.d = new Formatter(Locale.getDefault());
    }

    private void b() {
        if (this.f == null) {
            com.pubmatic.sdk.common.utility.l lVar = new com.pubmatic.sdk.common.utility.l(new a());
            this.f = lVar;
            lVar.start(this.e * 1000);
        }
    }

    public void destroy() {
        a();
        com.pubmatic.sdk.common.view.c cVar = this.b;
        if (cVar != null) {
            cVar.postDelayed(new b(), 1000L);
        }
    }

    public void invalidateWebView() {
        com.pubmatic.sdk.common.view.c cVar = this.b;
        if (cVar != null) {
            cVar.setWebViewClient(null);
            this.b.stopLoading();
            this.b.loadUrl("about:blank");
            this.b.clearHistory();
            this.b.destroy();
            this.b = null;
        }
    }

    public boolean isUserInteracted() {
        return this.c;
    }

    public void loadHTML(String str, String str2, boolean z) {
        if (this.b != null) {
            if (str == null) {
                if (str2 != null) {
                    Trace.endSection();
                    Trace.beginSection("POB Rendering");
                    this.b.loadUrl(str2);
                    return;
                }
                return;
            }
            try {
                if (z) {
                    this.d.format("<html><head><meta name=\"viewport\" content=\"user-scalable=0, width=device-width, initial-scale=1\"/><style>body{margin:0;padding:0;}div{display:block;width:100%%;height:100%%;}</style></head><body><div align=\"center\">%s</div></body></html>", str);
                } else {
                    this.d.format("<html><head><meta name=\"viewport\" content=\"user-scalable=0\"/><style>body{margin:0;padding:0;}</style></head><body><div align=\"center\">%s</div></body></html>", str);
                }
                String strValueOf = String.valueOf(this.d);
                this.d.close();
                Trace.endSection();
                Trace.beginSection("POB Rendering");
                this.b.loadDataWithBaseURL(str2, strValueOf, "text/html", StandardCharsets.UTF_8.name(), null);
                if (z) {
                    return;
                }
                b();
            } catch (OutOfMemoryError e) {
                e = e;
                notifyError(new com.pubmatic.sdk.common.h(1009, "Unable to render creative, due to " + e.getMessage()));
            } catch (IllegalFormatException e2) {
                e = e2;
                notifyError(new com.pubmatic.sdk.common.h(1009, "Unable to render creative, due to " + e.getMessage()));
            }
        }
    }

    public void notifyError(com.pubmatic.sdk.common.h hVar) {
        a();
        com.pubmatic.sdk.common.ui.e eVar = this.a;
        if (eVar != null) {
            eVar.onViewRenderingFailed(hVar);
        }
    }

    @Override // com.pubmatic.sdk.webrendering.ui.j
    public void onPageFinished(@NonNull WebView webView) {
        a();
        com.pubmatic.sdk.common.ui.e eVar = this.a;
        if (eVar != null) {
            eVar.onViewRendered(webView);
        }
    }

    @Override // com.pubmatic.sdk.webrendering.ui.j
    public void onReceivedError(@NonNull com.pubmatic.sdk.common.h hVar) {
        notifyError(hVar);
    }

    public void setRendererViewListener(com.pubmatic.sdk.common.ui.e eVar) {
        this.a = eVar;
    }

    public void setRenderingTimeout(int i) {
        this.e = i;
    }

    public void setUserInteracted(boolean z) {
        this.c = z;
    }

    @Override // com.pubmatic.sdk.webrendering.ui.j
    public boolean shouldOverrideUrlLoading(String str) {
        com.pubmatic.sdk.common.ui.e eVar = this.a;
        if (eVar == null || !this.c) {
            return false;
        }
        this.c = false;
        eVar.onViewClicked(str);
        return true;
    }

    private void a() {
        com.pubmatic.sdk.common.utility.l lVar = this.f;
        if (lVar != null) {
            lVar.cancel();
            this.f = null;
        }
    }
}
