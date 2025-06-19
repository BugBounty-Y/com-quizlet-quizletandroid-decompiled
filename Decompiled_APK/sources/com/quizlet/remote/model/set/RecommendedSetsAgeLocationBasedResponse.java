package com.quizlet.remote.model.set;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RecommendedSetsAgeLocationBasedResponse extends ApiResponse {
    public final RecommendedSetsAgeLocationBasedModels d;

    @m(generateAdapter = true)
    @Metadata
    public static final class RecommendedSetsAgeLocationBasedModels {
        public final List a;

        public RecommendedSetsAgeLocationBasedModels(List set) {
            Intrinsics.checkNotNullParameter(set, "set");
            this.a = set;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof RecommendedSetsAgeLocationBasedModels) && Intrinsics.b(this.a, ((RecommendedSetsAgeLocationBasedModels) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("RecommendedSetsAgeLocationBasedModels(set="), this.a);
        }
    }

    public RecommendedSetsAgeLocationBasedResponse(RecommendedSetsAgeLocationBasedModels models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RecommendedSetsAgeLocationBasedResponse) && Intrinsics.b(this.d, ((RecommendedSetsAgeLocationBasedResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RecommendedSetsAgeLocationBasedResponse(models=" + this.d + ")";
    }
}
