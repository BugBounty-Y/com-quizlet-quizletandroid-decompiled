package com.quizlet.quizletandroid.ui.setcreation.navigation;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.qutils.string.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends e {
    public final f a;

    public c(f title) {
        Intrinsics.checkNotNullParameter("https://help.quizlet.com/hc/articles/360029190271", DTBMetricsConfiguration.APSMETRICS_URL);
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = title;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        cVar.getClass();
        return this.a.equals(cVar.a);
    }

    public final int hashCode() {
        return this.a.hashCode() + 517270688;
    }

    public final String toString() {
        return "ShowResendEmailFaqPage(url=https://help.quizlet.com/hc/articles/360029190271, title=" + this.a + ")";
    }
}
