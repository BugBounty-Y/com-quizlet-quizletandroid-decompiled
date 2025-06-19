package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class TextAnnotationsList {

    @NotNull
    private final List<TextAnnotations> textAnnotations;

    @JsonCreator
    public TextAnnotationsList(@JsonProperty("textAnnotations") @NotNull List<TextAnnotations> textAnnotations) {
        Intrinsics.checkNotNullParameter(textAnnotations, "textAnnotations");
        this.textAnnotations = textAnnotations;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ TextAnnotationsList copy$default(TextAnnotationsList textAnnotationsList, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            list = textAnnotationsList.textAnnotations;
        }
        return textAnnotationsList.copy(list);
    }

    @NotNull
    public final List<TextAnnotations> component1() {
        return this.textAnnotations;
    }

    @NotNull
    public final TextAnnotationsList copy(@JsonProperty("textAnnotations") @NotNull List<TextAnnotations> textAnnotations) {
        Intrinsics.checkNotNullParameter(textAnnotations, "textAnnotations");
        return new TextAnnotationsList(textAnnotations);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof TextAnnotationsList) && Intrinsics.b(this.textAnnotations, ((TextAnnotationsList) obj).textAnnotations);
    }

    @NotNull
    public final List<TextAnnotations> getTextAnnotations() {
        return this.textAnnotations;
    }

    public int hashCode() {
        return this.textAnnotations.hashCode();
    }

    @NotNull
    public String toString() {
        return "TextAnnotationsList(textAnnotations=" + this.textAnnotations + ")";
    }
}
