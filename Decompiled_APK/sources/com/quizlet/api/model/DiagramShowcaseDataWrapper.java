package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DiagramShowcaseDataWrapper {

    @NotNull
    private List<DiagramShowcaseResponse> responses;

    @JsonCreator
    public DiagramShowcaseDataWrapper(@JsonProperty("responses") @NotNull List<DiagramShowcaseResponse> responses) {
        Intrinsics.checkNotNullParameter(responses, "responses");
        this.responses = responses;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ DiagramShowcaseDataWrapper copy$default(DiagramShowcaseDataWrapper diagramShowcaseDataWrapper, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            list = diagramShowcaseDataWrapper.responses;
        }
        return diagramShowcaseDataWrapper.copy(list);
    }

    @NotNull
    public final List<DiagramShowcaseResponse> component1() {
        return this.responses;
    }

    @NotNull
    public final DiagramShowcaseDataWrapper copy(@JsonProperty("responses") @NotNull List<DiagramShowcaseResponse> responses) {
        Intrinsics.checkNotNullParameter(responses, "responses");
        return new DiagramShowcaseDataWrapper(responses);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DiagramShowcaseDataWrapper) && Intrinsics.b(this.responses, ((DiagramShowcaseDataWrapper) obj).responses);
    }

    @NotNull
    public final List<DiagramShowcaseResponse> getResponses() {
        return this.responses;
    }

    public int hashCode() {
        return this.responses.hashCode();
    }

    public final void setResponses(@NotNull List<DiagramShowcaseResponse> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.responses = list;
    }

    @NotNull
    public String toString() {
        return "DiagramShowcaseDataWrapper(responses=" + this.responses + ")";
    }
}
