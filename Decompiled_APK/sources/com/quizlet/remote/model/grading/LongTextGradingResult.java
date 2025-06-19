package com.quizlet.remote.model.grading;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class LongTextGradingResult {
    public final RemoteLongTextGradingResult a;

    public LongTextGradingResult(@InterfaceC4853h(name = "longtextGradingResult") RemoteLongTextGradingResult remoteLongTextGradingResult) {
        this.a = remoteLongTextGradingResult;
    }

    @NotNull
    public final LongTextGradingResult copy(@InterfaceC4853h(name = "longtextGradingResult") RemoteLongTextGradingResult remoteLongTextGradingResult) {
        return new LongTextGradingResult(remoteLongTextGradingResult);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LongTextGradingResult) && Intrinsics.b(this.a, ((LongTextGradingResult) obj).a);
    }

    public final int hashCode() {
        RemoteLongTextGradingResult remoteLongTextGradingResult = this.a;
        if (remoteLongTextGradingResult == null) {
            return 0;
        }
        return remoteLongTextGradingResult.hashCode();
    }

    public final String toString() {
        return "LongTextGradingResult(longTextGradingResult=" + this.a + ")";
    }
}
