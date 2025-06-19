package com.quizlet.remote.model.achievements;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class StreaksHistoryResponse extends ApiResponse {
    public final HistoryDataResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class HistoryDataResponse {
        public final List a;

        public HistoryDataResponse(List dates) {
            Intrinsics.checkNotNullParameter(dates, "dates");
            this.a = dates;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof HistoryDataResponse) && Intrinsics.b(this.a, ((HistoryDataResponse) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("HistoryDataResponse(dates="), this.a);
        }
    }

    public StreaksHistoryResponse(HistoryDataResponse data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StreaksHistoryResponse) && Intrinsics.b(this.d, ((StreaksHistoryResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "StreaksHistoryResponse(data=" + this.d + ")";
    }
}
