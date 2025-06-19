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
public final class DiagramShowcaseResponse {

    @NotNull
    private DiagramShowcaseModels models;

    @NotNull
    private List<DiagramShowcaseCategory> orderedCategories;

    @JsonCreator
    public DiagramShowcaseResponse() {
        this(null, null, 3, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ DiagramShowcaseResponse copy$default(DiagramShowcaseResponse diagramShowcaseResponse, DiagramShowcaseModels diagramShowcaseModels, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            diagramShowcaseModels = diagramShowcaseResponse.models;
        }
        if ((i & 2) != 0) {
            list = diagramShowcaseResponse.orderedCategories;
        }
        return diagramShowcaseResponse.copy(diagramShowcaseModels, list);
    }

    @NotNull
    public final DiagramShowcaseModels component1() {
        return this.models;
    }

    @NotNull
    public final List<DiagramShowcaseCategory> component2() {
        return this.orderedCategories;
    }

    @NotNull
    public final DiagramShowcaseResponse copy(@JsonProperty("models") @NotNull DiagramShowcaseModels models, @JsonProperty("orderedCategories") @NotNull List<DiagramShowcaseCategory> orderedCategories) {
        Intrinsics.checkNotNullParameter(models, "models");
        Intrinsics.checkNotNullParameter(orderedCategories, "orderedCategories");
        return new DiagramShowcaseResponse(models, orderedCategories);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DiagramShowcaseResponse)) {
            return false;
        }
        DiagramShowcaseResponse diagramShowcaseResponse = (DiagramShowcaseResponse) obj;
        return Intrinsics.b(this.models, diagramShowcaseResponse.models) && Intrinsics.b(this.orderedCategories, diagramShowcaseResponse.orderedCategories);
    }

    @NotNull
    public final DiagramShowcaseModels getModels() {
        return this.models;
    }

    @NotNull
    public final List<DiagramShowcaseCategory> getOrderedCategories() {
        return this.orderedCategories;
    }

    public int hashCode() {
        return this.orderedCategories.hashCode() + (this.models.hashCode() * 31);
    }

    public final void setModels(@NotNull DiagramShowcaseModels diagramShowcaseModels) {
        Intrinsics.checkNotNullParameter(diagramShowcaseModels, "<set-?>");
        this.models = diagramShowcaseModels;
    }

    public final void setOrderedCategories(@NotNull List<DiagramShowcaseCategory> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.orderedCategories = list;
    }

    @NotNull
    public String toString() {
        return "DiagramShowcaseResponse(models=" + this.models + ", orderedCategories=" + this.orderedCategories + ")";
    }

    @JsonCreator
    public DiagramShowcaseResponse(@JsonProperty("models") @NotNull DiagramShowcaseModels models, @JsonProperty("orderedCategories") @NotNull List<DiagramShowcaseCategory> orderedCategories) {
        Intrinsics.checkNotNullParameter(models, "models");
        Intrinsics.checkNotNullParameter(orderedCategories, "orderedCategories");
        this.models = models;
        this.orderedCategories = orderedCategories;
    }

    public DiagramShowcaseResponse(DiagramShowcaseModels diagramShowcaseModels, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? new DiagramShowcaseModels(null, null, null, 7, null) : diagramShowcaseModels, (i & 2) != 0 ? K.a : list);
    }
}
