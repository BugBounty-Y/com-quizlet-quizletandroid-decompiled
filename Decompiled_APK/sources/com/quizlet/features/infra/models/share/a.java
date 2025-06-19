package com.quizlet.features.infra.models.share;

import androidx.compose.animation.d0;
import com.quizlet.qutils.string.f;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final f c;
    public final Function1 d;
    public final Function1 e;

    public a(String webUrl, String utmCampaign, f title, Function1 shareTextBuilder, Function1 onShareSheetShown) {
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        Intrinsics.checkNotNullParameter(utmCampaign, "utmCampaign");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(shareTextBuilder, "shareTextBuilder");
        Intrinsics.checkNotNullParameter(onShareSheetShown, "onShareSheetShown");
        this.a = webUrl;
        this.b = utmCampaign;
        this.c = title;
        this.d = shareTextBuilder;
        this.e = onShareSheetShown;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b.equals(aVar.b) && this.c.equals(aVar.c) && this.d.equals(aVar.d) && this.e.equals(aVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b)) * 31)) * 31);
    }

    public final String toString() {
        return "ShareRequestData(webUrl=" + this.a + ", utmCampaign=" + this.b + ", title=" + this.c + ", shareTextBuilder=" + this.d + ", onShareSheetShown=" + this.e + ")";
    }
}
