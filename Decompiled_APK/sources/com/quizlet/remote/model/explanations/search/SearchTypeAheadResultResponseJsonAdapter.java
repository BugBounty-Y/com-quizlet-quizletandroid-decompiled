package com.quizlet.remote.model.explanations.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
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
public final class SearchTypeAheadResultResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public SearchTypeAheadResultResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("data", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(SearchTypeAheadResultResponse.SearchSuggestionsData.class, m, "data");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        SearchTypeAheadResultResponse.SearchSuggestionsData searchSuggestionsData = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        PagingInfo pagingInfo = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                searchSuggestionsData = (SearchTypeAheadResultResponse.SearchSuggestionsData) this.b.a(reader);
                if (searchSuggestionsData == null) {
                    throw com.squareup.moshi.internal.b.k("data_", "data", reader);
                }
            } else if (iK0 == 1) {
                pagingInfo = (PagingInfo) this.c.a(reader);
                z = true;
            } else if (iK0 == 2) {
                list = (List) this.d.a(reader);
                z2 = true;
            } else if (iK0 == 3) {
                modelError = (ModelError) this.e.a(reader);
                z3 = true;
            }
        }
        reader.i();
        if (searchSuggestionsData == null) {
            throw com.squareup.moshi.internal.b.e("data_", "data", reader);
        }
        SearchTypeAheadResultResponse searchTypeAheadResultResponse = new SearchTypeAheadResultResponse(searchSuggestionsData);
        if (z) {
            searchTypeAheadResultResponse.a = pagingInfo;
        }
        if (z2) {
            searchTypeAheadResultResponse.b = list;
        }
        if (z3) {
            searchTypeAheadResultResponse.c = modelError;
        }
        return searchTypeAheadResultResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SearchTypeAheadResultResponse searchTypeAheadResultResponse = (SearchTypeAheadResultResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (searchTypeAheadResultResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("data");
        this.b.g(writer, searchTypeAheadResultResponse.d);
        writer.l("paging");
        this.c.g(writer, searchTypeAheadResultResponse.a);
        writer.l("validationErrors");
        this.d.g(writer, searchTypeAheadResultResponse.b);
        writer.l("error");
        this.e.g(writer, searchTypeAheadResultResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(51, "GeneratedJsonAdapter(SearchTypeAheadResultResponse)", "toString(...)");
    }
}
