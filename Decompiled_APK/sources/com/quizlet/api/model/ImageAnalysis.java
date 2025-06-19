package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@JsonDeserialize(using = ImageAnalysisDeserializer.class)
@Metadata
/* loaded from: classes2.dex */
public final class ImageAnalysis {

    @NotNull
    private final TextAnnotationsList imageAnalysis;

    @JsonCreator
    public ImageAnalysis(@JsonProperty("imageAnalysis") @NotNull TextAnnotationsList imageAnalysis) {
        Intrinsics.checkNotNullParameter(imageAnalysis, "imageAnalysis");
        this.imageAnalysis = imageAnalysis;
    }

    public static /* synthetic */ ImageAnalysis copy$default(ImageAnalysis imageAnalysis, TextAnnotationsList textAnnotationsList, int i, Object obj) {
        if ((i & 1) != 0) {
            textAnnotationsList = imageAnalysis.imageAnalysis;
        }
        return imageAnalysis.copy(textAnnotationsList);
    }

    @NotNull
    public final TextAnnotationsList component1() {
        return this.imageAnalysis;
    }

    @NotNull
    public final ImageAnalysis copy(@JsonProperty("imageAnalysis") @NotNull TextAnnotationsList imageAnalysis) {
        Intrinsics.checkNotNullParameter(imageAnalysis, "imageAnalysis");
        return new ImageAnalysis(imageAnalysis);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ImageAnalysis) && Intrinsics.b(this.imageAnalysis, ((ImageAnalysis) obj).imageAnalysis);
    }

    @NotNull
    public final TextAnnotationsList getImageAnalysis() {
        return this.imageAnalysis;
    }

    public int hashCode() {
        return this.imageAnalysis.hashCode();
    }

    @NotNull
    public String toString() {
        return "ImageAnalysis(imageAnalysis=" + this.imageAnalysis + ")";
    }
}
