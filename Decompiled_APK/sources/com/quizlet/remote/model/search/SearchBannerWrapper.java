package com.quizlet.remote.model.search;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SearchBannerWrapper {
    public final String a;
    public final String b;
    public final String c;
    public final String d;

    public SearchBannerWrapper(String str, String str2, String str3, String str4) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchBannerWrapper)) {
            return false;
        }
        SearchBannerWrapper searchBannerWrapper = (SearchBannerWrapper) obj;
        return Intrinsics.b(this.a, searchBannerWrapper.a) && Intrinsics.b(this.b, searchBannerWrapper.b) && Intrinsics.b(this.c, searchBannerWrapper.c) && Intrinsics.b(this.d, searchBannerWrapper.d);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.c;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.d;
        return iHashCode3 + (str4 != null ? str4.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchBannerWrapper(icon=");
        sb.append(this.a);
        sb.append(", name=");
        sb.append(this.b);
        sb.append(", type=");
        sb.append(this.c);
        sb.append(", url=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }

    public /* synthetic */ SearchBannerWrapper(String str, String str2, String str3, String str4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, (i & 8) != 0 ? null : str4);
    }
}
