package com.onetrust.otpublishers.headless.UI.extensions;

import android.view.View;
import androidx.core.view.C1038b;
import androidx.core.view.accessibility.d;
import androidx.core.view.accessibility.e;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends C1038b {
    public final /* synthetic */ int d;
    public final /* synthetic */ String e;

    public /* synthetic */ c(String str, int i) {
        this.d = i;
        this.e = str;
    }

    @Override // androidx.core.view.C1038b
    public final void d(View host, e info) {
        switch (this.d) {
            case 0:
                Intrinsics.checkNotNullParameter(host, "host");
                Intrinsics.checkNotNullParameter(info, "info");
                this.a.onInitializeAccessibilityNodeInfo(host, info.a);
                info.b(new d(16, this.e));
                break;
            default:
                this.a.onInitializeAccessibilityNodeInfo(host, info.a);
                info.b(new d(16, this.e));
                break;
        }
    }
}
