package com.pubmatic.sdk.video.player;

import android.R;
import android.annotation.SuppressLint;
import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import java.nio.charset.StandardCharsets;
import java.util.Formatter;
import java.util.IllegalFormatException;
import java.util.Locale;

/* loaded from: classes2.dex */
public abstract class l extends FrameLayout implements com.pubmatic.sdk.common.ui.e, com.pubmatic.sdk.webrendering.ui.k {
    private com.pubmatic.sdk.webrendering.ui.i a;
    private com.pubmatic.sdk.common.view.c b;

    public class a extends com.pubmatic.sdk.webrendering.ui.i {
        public a(com.pubmatic.sdk.common.view.c cVar, com.pubmatic.sdk.webrendering.ui.l lVar) {
            super(cVar, lVar);
        }

        @Override // com.pubmatic.sdk.webrendering.ui.i
        public void loadHTML(String str, String str2, boolean z) {
            if (str == null) {
                l.this.b.loadUrl(str2);
                return;
            }
            try {
                Formatter formatter = new Formatter(Locale.getDefault());
                formatter.format("<html><head><meta name=\"viewport\" content=\"user-scalable=0, width=device-width, initial-scale=1\"/><style>body{margin:0;padding:0;}div{display:block;width:100%%;height:100%%;}</style></head><body><div align=\"center\">%s</div></body></html>", str);
                String strValueOf = String.valueOf(formatter);
                formatter.close();
                l.this.b.loadDataWithBaseURL(null, strValueOf, "text/html", StandardCharsets.UTF_8.name(), null);
            } catch (IllegalFormatException e) {
                notifyError(new com.pubmatic.sdk.common.h(1009, "Unable to render creative, due to " + e.getMessage()));
            }
        }
    }

    public l(@NonNull Context context) {
        super(context);
        setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        setBackgroundColor(getResources().getColor(R.color.transparent));
    }

    @SuppressLint({"SetJavaScriptEnabled"})
    public com.pubmatic.sdk.common.view.c createWebView(@NonNull Context context) {
        com.pubmatic.sdk.common.view.c cVarCreateInstance = com.pubmatic.sdk.common.view.c.createInstance(context);
        if (cVarCreateInstance != null) {
            cVarCreateInstance.getSettings().setJavaScriptEnabled(true);
            cVarCreateInstance.getSettings().setCacheMode(2);
            cVarCreateInstance.setScrollBarStyle(0);
        }
        return cVarCreateInstance;
    }

    public void destroy() {
        invalidateRenderer();
    }

    public void invalidateRenderer() {
        com.pubmatic.sdk.webrendering.ui.i iVar = this.a;
        if (iVar != null) {
            iVar.destroy();
            this.a = null;
        }
    }

    public abstract /* synthetic */ void onRenderProcessGone();

    public abstract /* synthetic */ void onViewClicked(String str);

    public abstract /* synthetic */ void onViewRendered(@NonNull View view);

    public abstract /* synthetic */ void onViewRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar);

    public boolean renderVastHTMLView(@NonNull com.pubmatic.sdk.common.base.c cVar) {
        com.pubmatic.sdk.common.view.c cVarCreateWebView = createWebView(getContext());
        this.b = cVarCreateWebView;
        if (cVarCreateWebView == null) {
            return false;
        }
        com.pubmatic.sdk.webrendering.ui.l lVar = new com.pubmatic.sdk.webrendering.ui.l(this);
        lVar.disableMultipleOnPageFinished(true);
        a aVar = new a(this.b, lVar);
        this.a = aVar;
        aVar.setRendererViewListener(this);
        String renderableContent = cVar.getRenderableContent();
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(renderableContent)) {
            return false;
        }
        if (renderableContent.toLowerCase().startsWith("http")) {
            this.a.loadHTML(null, renderableContent, cVar.isCompanion());
        } else {
            this.a.loadHTML(renderableContent, "", cVar.isCompanion());
        }
        return true;
    }
}
