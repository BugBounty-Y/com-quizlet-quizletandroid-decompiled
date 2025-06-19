package com.onetrust.otpublishers.headless.UI.Helper;

import android.content.Context;
import android.text.style.ClickableSpan;
import android.text.style.URLSpan;
import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends ClickableSpan {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;
    public final /* synthetic */ URLSpan c;

    public /* synthetic */ d(Context context, URLSpan uRLSpan, int i) {
        this.a = i;
        this.b = context;
        this.c = uRLSpan;
    }

    @Override // android.text.style.ClickableSpan
    public final void onClick(View view) {
        switch (this.a) {
            case 0:
                com.onetrust.otpublishers.headless.Internal.a.c(this.b, this.c.getURL());
                break;
            default:
                Intrinsics.checkNotNullParameter(view, "view");
                com.onetrust.otpublishers.headless.Internal.a.c(this.b, this.c.getURL());
                break;
        }
    }
}
