package com.quizlet.quizletandroid.ui.common.ads.prebid.creators;

import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.compose.animation.d0;
import com.google.android.gms.ads.h;
import com.quizlet.login.magiclink.ui.e;
import com.quizlet.quizletandroid.ui.common.ads.C4634a;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final com.quizlet.ads.c a;
    public final h b;
    public final ViewGroup c;
    public final WindowManager d;
    public final C4634a e;
    public final Map f;
    public final Map g;
    public final e h;

    public b(com.quizlet.ads.c adUnit, h adSize, ViewGroup adContainer, WindowManager windowManager, C4634a adMetadata, Map basicAdsTargets, Map customTargets, e partnerTargeting) {
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        Intrinsics.checkNotNullParameter(adSize, "adSize");
        Intrinsics.checkNotNullParameter(adContainer, "adContainer");
        Intrinsics.checkNotNullParameter(windowManager, "windowManager");
        Intrinsics.checkNotNullParameter(adMetadata, "adMetadata");
        Intrinsics.checkNotNullParameter(basicAdsTargets, "basicAdsTargets");
        Intrinsics.checkNotNullParameter(customTargets, "customTargets");
        Intrinsics.checkNotNullParameter(partnerTargeting, "partnerTargeting");
        this.a = adUnit;
        this.b = adSize;
        this.c = adContainer;
        this.d = windowManager;
        this.e = adMetadata;
        this.f = basicAdsTargets;
        this.g = customTargets;
        this.h = partnerTargeting;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e) && Intrinsics.b(this.f, bVar.f) && this.g.equals(bVar.g) && this.h.equals(bVar.h);
    }

    public final int hashCode() {
        return this.h.hashCode() + assistantMode.refactored.a.d(assistantMode.refactored.a.d((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b.c)) * 31)) * 31)) * 31, 31, this.f), 31, this.g);
    }

    public final String toString() {
        return "Input(adUnit=" + this.a + ", adSize=" + this.b + ", adContainer=" + this.c + ", windowManager=" + this.d + ", adMetadata=" + this.e + ", basicAdsTargets=" + this.f + ", customTargets=" + this.g + ", partnerTargeting=" + this.h + ")";
    }
}
