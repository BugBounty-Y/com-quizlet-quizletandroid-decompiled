package com.pubmatic.sdk.common.view;

import android.content.Context;
import android.content.MutableContextWrapper;
import android.view.KeyEvent;
import android.webkit.WebView;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class c extends WebView {
    private b a;
    private a b;
    private MutableContextWrapper c;

    public c(@NonNull Context context) {
        super(context);
        setBackgroundColor(0);
    }

    public static c createInstance(@NonNull Context context) {
        c cVar;
        try {
            MutableContextWrapper mutableContextWrapper = new MutableContextWrapper(context);
            cVar = new c(mutableContextWrapper);
            try {
                cVar.c = mutableContextWrapper;
                return cVar;
            } catch (Exception unused) {
                POBLog.error("POBWebView", "Unable to instantiate Web View", new Object[0]);
                return cVar;
            }
        } catch (Exception unused2) {
            cVar = null;
        }
    }

    @Override // android.webkit.WebView, android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyDown(int i, KeyEvent keyEvent) {
        if (keyEvent.getAction() == 0) {
            if (i == 4) {
                b bVar = this.a;
                if (bVar != null) {
                    bVar.onBackPress();
                    return true;
                }
            } else {
                POBLog.debug("POBWebView", android.support.v4.media.session.a.f(i, "default case, keyCode:"), new Object[0]);
            }
        }
        return super.onKeyDown(i, keyEvent);
    }

    @Override // android.webkit.WebView, android.view.View
    public void onWindowFocusChanged(boolean z) {
        super.onWindowFocusChanged(z);
        POBLog.debug("POBWebView", "hasWindowFocus :" + z, new Object[0]);
        a aVar = this.b;
        if (aVar != null) {
            aVar.onFocusChanged(z);
        }
    }

    public void setBaseContext(@NonNull Context context) {
        MutableContextWrapper mutableContextWrapper = this.c;
        if (mutableContextWrapper != null) {
            mutableContextWrapper.setBaseContext(context);
        }
    }

    public void setOnfocusChangedListener(a aVar) {
        this.b = aVar;
    }

    public void setWebViewBackPress(b bVar) {
        this.a = bVar;
    }
}
