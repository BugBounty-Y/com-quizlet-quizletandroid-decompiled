package com.quizlet.remote.model.folder;

import com.quizlet.remote.model.base.ApiResponse;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SubfolderNameRecommendationsResponse extends ApiResponse {
    public final Models d;

    @com.squareup.moshi.m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;

        public Models(List list) {
            this.a = list;
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
            return android.support.v4.media.session.a.n(")", new StringBuilder("Models(subfolderNames="), this.a);
        }
    }

    public SubfolderNameRecommendationsResponse(Models models) {
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SubfolderNameRecommendationsResponse) && Intrinsics.b(this.d, ((SubfolderNameRecommendationsResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "SubfolderNameRecommendationsResponse(models=" + this.d + ")";
    }
}
