package com.pubmatic.sdk.common.utility;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.browser.POBInternalBrowserActivity;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class n {

    @NonNull
    private final m a;

    @NonNull
    private final Context b;
    private boolean c = false;

    public class a implements com.pubmatic.sdk.common.browser.a {
        final /* synthetic */ String a;

        public a(String str) {
            this.a = str;
        }

        @Override // com.pubmatic.sdk.common.browser.a
        public void onBrowserDismiss() {
            POBLog.debug("POBUrlHandler", "Dismissed device default browser. url :%s", this.a);
            n.this.a.onInternalBrowserClose(this.a);
            n.this.c = false;
        }

        @Override // com.pubmatic.sdk.common.browser.a
        public void onBrowserStart() {
            n.this.a.onInternalBrowserOpen(this.a);
        }

        @Override // com.pubmatic.sdk.common.browser.a
        public void onExternalBrowserClick(@NonNull String str) {
            POBLog.debug("POBUrlHandler", "Opening current page in device's default browser. url :%s", str);
            if (o.openExternalBrowser(n.this.b, str)) {
                n.this.a.onLeaveApp(str);
            } else {
                n.this.a.onErrorOpenUrl(str);
                POBLog.warn("POBUrlHandler", "Unable to open url in external browser from internal browser %s", str);
            }
        }
    }

    public n(@NonNull Context context, @NonNull m mVar) {
        this.b = context;
        this.a = mVar;
    }

    public void open(String str, String str2) {
        if (!o.isStringValueNullOrEmpty(str)) {
            POBLog.debug("POBUrlHandler", "Opening landing page with url: %s", str);
            open(str);
        } else {
            if (!o.isStringValueNullOrEmpty(str2)) {
                POBLog.debug("POBUrlHandler", "Opening landing page with url: %s", str);
                open(str2);
                return;
            }
            POBLog.debug("POBUrlHandler", AbstractC0147y.d("Failed to open url: ", str), new Object[0]);
            m mVar = this.a;
            if (str == null) {
                str = "";
            }
            mVar.onErrorOpenUrl(str);
        }
    }

    public void open(@NonNull String str) {
        if (e.validateAndRedirect(this.b, str)) {
            POBLog.debug("POBUrlHandler", "Deep link success", new Object[0]);
            this.a.onLeaveApp(str);
            return;
        }
        if (com.pubmatic.sdk.common.i.getSdkConfig().isUseInternalBrowser()) {
            if (!this.c) {
                this.c = true;
                POBInternalBrowserActivity.startNewActivity(this.b, str, new a(str));
                return;
            } else {
                POBLog.warn("POBUrlHandler", "Internal browser already displayed", new Object[0]);
                return;
            }
        }
        if (o.openExternalBrowser(this.b, str)) {
            this.a.onLeaveApp(str);
        } else {
            POBLog.warn("POBUrlHandler", "Unable to open url in external browser %s", str);
            this.a.onErrorOpenUrl(str);
        }
    }
}
