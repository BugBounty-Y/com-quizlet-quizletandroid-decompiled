package com.quizlet.remote.model.search;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SearchBannerResponseWrapper extends ApiResponse {
    public final SearchBannerWrapper d;

    public SearchBannerResponseWrapper(SearchBannerWrapper searchBannerWrapper) {
        this.d = searchBannerWrapper;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SearchBannerResponseWrapper) && Intrinsics.b(this.d, ((SearchBannerResponseWrapper) obj).d);
    }

    public final int hashCode() {
        SearchBannerWrapper searchBannerWrapper = this.d;
        if (searchBannerWrapper == null) {
            return 0;
        }
        return searchBannerWrapper.hashCode();
    }

    public final String toString() {
        return "SearchBannerResponseWrapper(banner=" + this.d + ")";
    }

    public /* synthetic */ SearchBannerResponseWrapper(SearchBannerWrapper searchBannerWrapper, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : searchBannerWrapper);
    }
}
