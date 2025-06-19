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
public final class ExplanationsSearchResultResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;

        public Models(@InterfaceC4853h(name = "explanationsSearchResults") List<? extends b> list) {
            this.a = list;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "explanationsSearchResults") List<? extends b> list) {
            return new Models(list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Models) && Intrinsics.b(this.a, ((Models) obj).a);
        }

        public final int hashCode() {
            List list = this.a;
            if (list == null) {
                return 0;
            }
            return list.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("Models(explanationsSearchResult="), this.a);
        }
    }

    public ExplanationsSearchResultResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final ExplanationsSearchResultResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new ExplanationsSearchResultResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ExplanationsSearchResultResponse) && Intrinsics.b(this.d, ((ExplanationsSearchResultResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "ExplanationsSearchResultResponse(models=" + this.d + ")";
    }
}
