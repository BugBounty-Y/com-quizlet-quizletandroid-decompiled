package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ImageAnalysisResponse {

    @NotNull
    private List<ImageAnalysisResponseData> responses;

    @JsonCreator
    public ImageAnalysisResponse() {
        this(null, 1, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ ImageAnalysisResponse copy$default(ImageAnalysisResponse imageAnalysisResponse, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            list = imageAnalysisResponse.responses;
        }
        return imageAnalysisResponse.copy(list);
    }

    @NotNull
    public final List<ImageAnalysisResponseData> component1() {
        return this.responses;
    }

    @NotNull
    public final ImageAnalysisResponse copy(@JsonProperty("responses") @NotNull List<ImageAnalysisResponseData> responses) {
        Intrinsics.checkNotNullParameter(responses, "responses");
        return new ImageAnalysisResponse(responses);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ImageAnalysisResponse) && Intrinsics.b(this.responses, ((ImageAnalysisResponse) obj).responses);
    }

    @NotNull
    public final List<ImageAnalysisResponseData> getResponses() {
        return this.responses;
    }

    public int hashCode() {
        return this.responses.hashCode();
    }

    public final void setResponses(@NotNull List<ImageAnalysisResponseData> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.responses = list;
    }

    @NotNull
    public String toString() {
        return "ImageAnalysisResponse(responses=" + this.responses + ")";
    }

    @JsonCreator
    public ImageAnalysisResponse(@JsonProperty("responses") @NotNull List<ImageAnalysisResponseData> responses) {
        Intrinsics.checkNotNullParameter(responses, "responses");
        this.responses = responses;
    }

    public ImageAnalysisResponse(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list);
    }
}
