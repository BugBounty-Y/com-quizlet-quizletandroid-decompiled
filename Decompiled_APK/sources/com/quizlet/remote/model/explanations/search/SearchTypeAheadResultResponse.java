package com.quizlet.remote.model.explanations.search;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SearchTypeAheadResultResponse extends ApiResponse {
    public final SearchSuggestionsData d;

    @m(generateAdapter = true)
    @Metadata
    public static final class SearchSuggestionsData {
        public final SearchSuggestionsWrapper a;

        public SearchSuggestionsData(@InterfaceC4853h(name = "suggestions") @NotNull SearchSuggestionsWrapper suggestionsWrapper) {
            Intrinsics.checkNotNullParameter(suggestionsWrapper, "suggestionsWrapper");
            this.a = suggestionsWrapper;
        }

        @NotNull
        public final SearchSuggestionsData copy(@InterfaceC4853h(name = "suggestions") @NotNull SearchSuggestionsWrapper suggestionsWrapper) {
            Intrinsics.checkNotNullParameter(suggestionsWrapper, "suggestionsWrapper");
            return new SearchSuggestionsData(suggestionsWrapper);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof SearchSuggestionsData) && Intrinsics.b(this.a, ((SearchSuggestionsData) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return "SearchSuggestionsData(suggestionsWrapper=" + this.a + ")";
        }
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class SearchSuggestionsWrapper {
        public final String a;
        public final List b;

        public SearchSuggestionsWrapper(String requestId, List suggestions) {
            Intrinsics.checkNotNullParameter(requestId, "requestId");
            Intrinsics.checkNotNullParameter(suggestions, "suggestions");
            this.a = requestId;
            this.b = suggestions;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SearchSuggestionsWrapper)) {
                return false;
            }
            SearchSuggestionsWrapper searchSuggestionsWrapper = (SearchSuggestionsWrapper) obj;
            return Intrinsics.b(this.a, searchSuggestionsWrapper.a) && Intrinsics.b(this.b, searchSuggestionsWrapper.b);
        }

        public final int hashCode() {
            return this.b.hashCode() + (this.a.hashCode() * 31);
        }

        public final String toString() {
            return "SearchSuggestionsWrapper(requestId=" + this.a + ", suggestions=" + this.b + ")";
        }
    }

    public SearchTypeAheadResultResponse(SearchSuggestionsData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SearchTypeAheadResultResponse) && Intrinsics.b(this.d, ((SearchTypeAheadResultResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "SearchTypeAheadResultResponse(data=" + this.d + ")";
    }
}
