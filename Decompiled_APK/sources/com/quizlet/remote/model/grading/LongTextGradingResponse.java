package com.quizlet.remote.model.grading;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class LongTextGradingResponse extends ApiResponse {
    public final LongTextGradingResult d;

    public LongTextGradingResponse(@InterfaceC4853h(name = "data") LongTextGradingResult longTextGradingResult) {
        this.d = longTextGradingResult;
    }

    @NotNull
    public final LongTextGradingResponse copy(@InterfaceC4853h(name = "data") LongTextGradingResult longTextGradingResult) {
        return new LongTextGradingResponse(longTextGradingResult);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LongTextGradingResponse) && Intrinsics.b(this.d, ((LongTextGradingResponse) obj).d);
    }

    public final int hashCode() {
        LongTextGradingResult longTextGradingResult = this.d;
        if (longTextGradingResult == null) {
            return 0;
        }
        return longTextGradingResult.hashCode();
    }

    public final String toString() {
        return "LongTextGradingResponse(data=" + this.d + ")";
    }
}
