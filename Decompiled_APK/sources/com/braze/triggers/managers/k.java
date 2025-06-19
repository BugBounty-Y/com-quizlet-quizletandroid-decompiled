package com.braze.triggers.managers;

import android.net.Uri;
import com.braze.ui.inappmessage.listeners.DefaultInAppMessageWebViewClientListener;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Uri b;
    public final /* synthetic */ String c;

    public /* synthetic */ k(Uri uri, String str, int i) {
        this.a = i;
        this.b = uri;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.a(this.b, this.c);
            default:
                return DefaultInAppMessageWebViewClientListener.onOtherUrlAction$lambda$12(this.b, this.c);
        }
    }
}
