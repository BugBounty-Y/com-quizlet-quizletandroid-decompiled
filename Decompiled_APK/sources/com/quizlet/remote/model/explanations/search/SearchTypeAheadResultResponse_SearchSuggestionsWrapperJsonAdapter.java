package com.quizlet.remote.model.explanations.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.search.SearchTypeAheadResultResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchTypeAheadResultResponse_SearchSuggestionsWrapperJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public SearchTypeAheadResultResponse_SearchSuggestionsWrapperJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("requestId", "suggestions");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "requestId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteSearchSuggestion.class), m, "suggestions");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("requestId", "requestId", reader);
                }
            } else if (iK0 == 1 && (list = (List) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("suggestions", "suggestions", reader);
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("requestId", "requestId", reader);
        }
        if (list != null) {
            return new SearchTypeAheadResultResponse.SearchSuggestionsWrapper(str, list);
        }
        throw com.squareup.moshi.internal.b.e("suggestions", "suggestions", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SearchTypeAheadResultResponse.SearchSuggestionsWrapper searchSuggestionsWrapper = (SearchTypeAheadResultResponse.SearchSuggestionsWrapper) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (searchSuggestionsWrapper == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("requestId");
        this.b.g(writer, searchSuggestionsWrapper.a);
        writer.l("suggestions");
        this.c.g(writer, searchSuggestionsWrapper.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(76, "GeneratedJsonAdapter(SearchTypeAheadResultResponse.SearchSuggestionsWrapper)", "toString(...)");
    }
}
