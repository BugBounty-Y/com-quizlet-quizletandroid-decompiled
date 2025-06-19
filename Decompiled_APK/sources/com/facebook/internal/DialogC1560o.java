package com.facebook.internal;

import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.facebook.internal.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class DialogC1560o extends S {
    public static final /* synthetic */ int o = 0;
    public boolean n;

    public static void g(DialogC1560o this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        super.cancel();
    }

    @Override // com.facebook.internal.S
    public final Bundle c(String str) {
        Bundle bundleI = J.I(Uri.parse(str).getQuery());
        String string = bundleI.getString("bridge_args");
        bundleI.remove("bridge_args");
        if (!J.D(string)) {
            try {
                bundleI.putBundle("com.facebook.platform.protocol.BRIDGE_ARGS", AbstractC1551f.a(new JSONObject(string)));
            } catch (JSONException unused) {
                com.facebook.o oVar = com.facebook.o.a;
            }
        }
        String string2 = bundleI.getString("method_results");
        bundleI.remove("method_results");
        if (!J.D(string2)) {
            try {
                bundleI.putBundle("com.facebook.platform.protocol.RESULT_ARGS", AbstractC1551f.a(new JSONObject(string2)));
            } catch (JSONException unused2) {
                com.facebook.o oVar2 = com.facebook.o.a;
            }
        }
        bundleI.remove("version");
        C c = C.a;
        int iIntValue = 0;
        if (!com.facebook.internal.instrument.crashshield.a.b(C.class)) {
            try {
                iIntValue = C.d[0].intValue();
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(C.class, th);
            }
        }
        bundleI.putInt("com.facebook.platform.protocol.PROTOCOL_VERSION", iIntValue);
        return bundleI;
    }

    @Override // com.facebook.internal.S, android.app.Dialog, android.content.DialogInterface
    public final void cancel() {
        Q q = this.d;
        if (!this.k || this.i || q == null || !q.isShown()) {
            super.cancel();
        } else {
            if (this.n) {
                return;
            }
            this.n = true;
            q.loadUrl("javascript:(function() {  var event = document.createEvent('Event');  event.initEvent('fbPlatformDialogMustClose',true,true);  document.dispatchEvent(event);})();");
            new Handler(Looper.getMainLooper()).postDelayed(new androidx.compose.ui.text.input.C(this, 20), 1500L);
        }
    }
}
