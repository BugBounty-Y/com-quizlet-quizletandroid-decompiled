package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ImageAnalysisResponseData {

    @NotNull
    private ImageAnalysis data;

    @JsonCreator
    public ImageAnalysisResponseData(@JsonProperty("data") @NotNull ImageAnalysis data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.data = data;
    }

    public static /* synthetic */ ImageAnalysisResponseData copy$default(ImageAnalysisResponseData imageAnalysisResponseData, ImageAnalysis imageAnalysis, int i, Object obj) {
        if ((i & 1) != 0) {
            imageAnalysis = imageAnalysisResponseData.data;
        }
        return imageAnalysisResponseData.copy(imageAnalysis);
    }

    @NotNull
    public final ImageAnalysis component1() {
        return this.data;
    }

    @NotNull
    public final ImageAnalysisResponseData copy(@JsonProperty("data") @NotNull ImageAnalysis data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new ImageAnalysisResponseData(data);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ImageAnalysisResponseData) && Intrinsics.b(this.data, ((ImageAnalysisResponseData) obj).data);
    }

    @NotNull
    public final ImageAnalysis getData() {
        return this.data;
    }

    public int hashCode() {
        return this.data.hashCode();
    }

    public final void setData(@NotNull ImageAnalysis imageAnalysis) {
        Intrinsics.checkNotNullParameter(imageAnalysis, "<set-?>");
        this.data = imageAnalysis;
    }

    @NotNull
    public String toString() {
        return "ImageAnalysisResponseData(data=" + this.data + ")";
    }
}
