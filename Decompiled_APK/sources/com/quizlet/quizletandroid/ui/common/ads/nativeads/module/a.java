package com.quizlet.quizletandroid.ui.common.ads.nativeads.module;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final boolean a;
    public final String b;
    public final boolean c;

    public a(String contentWebUrl, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(contentWebUrl, "contentWebUrl");
        this.a = z;
        this.b = contentWebUrl;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.e(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AdsMetadata(isAdFeatureEnabled=");
        sb.append(this.a);
        sb.append(", contentWebUrl=");
        sb.append(this.b);
        sb.append(", isUnderAgeForAds=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
