package com.quizlet.remote.model.explanations.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.search.SearchTypeAheadResultResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchTypeAheadResultResponse_SearchSuggestionsDataJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public SearchTypeAheadResultResponse_SearchSuggestionsDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("suggestions");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(SearchTypeAheadResultResponse.SearchSuggestionsWrapper.class, M.a, "suggestionsWrapper");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        SearchTypeAheadResultResponse.SearchSuggestionsWrapper searchSuggestionsWrapper = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (searchSuggestionsWrapper = (SearchTypeAheadResultResponse.SearchSuggestionsWrapper) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("suggestionsWrapper", "suggestions", reader);
            }
        }
        reader.i();
        if (searchSuggestionsWrapper != null) {
            return new SearchTypeAheadResultResponse.SearchSuggestionsData(searchSuggestionsWrapper);
        }
        throw com.squareup.moshi.internal.b.e("suggestionsWrapper", "suggestions", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SearchTypeAheadResultResponse.SearchSuggestionsData searchSuggestionsData = (SearchTypeAheadResultResponse.SearchSuggestionsData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (searchSuggestionsData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("suggestions");
        this.b.g(writer, searchSuggestionsData.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(73, "GeneratedJsonAdapter(SearchTypeAheadResultResponse.SearchSuggestionsData)", "toString(...)");
    }
}
