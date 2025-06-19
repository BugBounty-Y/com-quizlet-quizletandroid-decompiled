package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import android.webkit.JavascriptInterface;

/* renamed from: com.google.android.gms.internal.ads.Ae, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1663Ae {
    public final ViewTreeObserverOnGlobalLayoutListenerC2829xe a;
    public final Ts b;

    public C1663Ae(ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe, Ts ts) {
        this.b = ts;
        this.a = viewTreeObserverOnGlobalLayoutListenerC2829xe;
    }

    @JavascriptInterface
    public String getClickSignals(String str) {
        if (TextUtils.isEmpty(str)) {
            com.google.android.gms.ads.internal.util.A.l("Click string is empty, not proceeding.");
            return "";
        }
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        P4 p4 = viewTreeObserverOnGlobalLayoutListenerC2829xe.b;
        if (p4 == null) {
            com.google.android.gms.ads.internal.util.A.l("Signal utils is empty, ignoring.");
            return "";
        }
        N4 n4 = p4.b;
        if (n4 == null) {
            com.google.android.gms.ads.internal.util.A.l("Signals object is empty, ignoring.");
            return "";
        }
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe.getContext() != null) {
            return n4.f(viewTreeObserverOnGlobalLayoutListenerC2829xe.getContext(), str, viewTreeObserverOnGlobalLayoutListenerC2829xe, viewTreeObserverOnGlobalLayoutListenerC2829xe.a.a);
        }
        com.google.android.gms.ads.internal.util.A.l("Context is null, ignoring.");
        return "";
    }

    @JavascriptInterface
    public String getViewSignals() {
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        P4 p4 = viewTreeObserverOnGlobalLayoutListenerC2829xe.b;
        if (p4 == null) {
            com.google.android.gms.ads.internal.util.A.l("Signal utils is empty, ignoring.");
            return "";
        }
        N4 n4 = p4.b;
        if (n4 == null) {
            com.google.android.gms.ads.internal.util.A.l("Signals object is empty, ignoring.");
            return "";
        }
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe.getContext() != null) {
            return n4.i(viewTreeObserverOnGlobalLayoutListenerC2829xe.getContext(), viewTreeObserverOnGlobalLayoutListenerC2829xe, viewTreeObserverOnGlobalLayoutListenerC2829xe.a.a);
        }
        com.google.android.gms.ads.internal.util.A.l("Context is null, ignoring.");
        return "";
    }

    @JavascriptInterface
    public void notify(String str) {
        if (TextUtils.isEmpty(str)) {
            com.google.android.gms.ads.internal.util.client.i.h("URL is empty, ignoring message");
        } else {
            com.google.android.gms.ads.internal.util.F.l.post(new Qv(19, this, str));
        }
    }
}
