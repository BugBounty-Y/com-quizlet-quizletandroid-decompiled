package com.quizlet.quizletandroid.ui.common.ads;

import android.view.ViewGroup;
import android.view.WindowManager;
import com.braze.C1480f;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H {
    public final com.quizlet.ads.c a;
    public final ViewGroup b;
    public final WindowManager c;
    public final C4634a d;
    public final Map e;
    public final Map f;
    public final C1480f g;

    public H(com.quizlet.ads.c adUnit, ViewGroup adContainer, WindowManager windowManager, C4634a adMetadata, Map basicAdsTargets, Map customTargets, C1480f partnerTargeting) {
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        Intrinsics.checkNotNullParameter(adContainer, "adContainer");
        Intrinsics.checkNotNullParameter(windowManager, "windowManager");
        Intrinsics.checkNotNullParameter(adMetadata, "adMetadata");
        Intrinsics.checkNotNullParameter(basicAdsTargets, "basicAdsTargets");
        Intrinsics.checkNotNullParameter(customTargets, "customTargets");
        Intrinsics.checkNotNullParameter(partnerTargeting, "partnerTargeting");
        this.a = adUnit;
        this.b = adContainer;
        this.c = windowManager;
        this.d = adMetadata;
        this.e = basicAdsTargets;
        this.f = customTargets;
        this.g = partnerTargeting;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        return this.a == h.a && Intrinsics.b(this.b, h.b) && Intrinsics.b(this.c, h.c) && Intrinsics.b(this.d, h.d) && Intrinsics.b(this.e, h.e) && this.f.equals(h.f) && this.g.equals(h.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + assistantMode.refactored.a.d(assistantMode.refactored.a.d((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31, 31, this.e), 31, this.f);
    }

    public final String toString() {
        return "Input(adUnit=" + this.a + ", adContainer=" + this.b + ", windowManager=" + this.c + ", adMetadata=" + this.d + ", basicAdsTargets=" + this.e + ", customTargets=" + this.f + ", partnerTargeting=" + this.g + ")";
    }
}
