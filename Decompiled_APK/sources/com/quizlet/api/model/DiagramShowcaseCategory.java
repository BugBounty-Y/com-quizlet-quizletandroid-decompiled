package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DiagramShowcaseCategory {

    @NotNull
    private String category;

    @NotNull
    private List<Long> setIds;

    @JsonCreator
    public DiagramShowcaseCategory(@JsonProperty("category") @NotNull String category, @JsonProperty("setIds") @NotNull List<Long> setIds) {
        Intrinsics.checkNotNullParameter(category, "category");
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        this.category = category;
        this.setIds = setIds;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ DiagramShowcaseCategory copy$default(DiagramShowcaseCategory diagramShowcaseCategory, String str, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            str = diagramShowcaseCategory.category;
        }
        if ((i & 2) != 0) {
            list = diagramShowcaseCategory.setIds;
        }
        return diagramShowcaseCategory.copy(str, list);
    }

    @NotNull
    public final String component1() {
        return this.category;
    }

    @NotNull
    public final List<Long> component2() {
        return this.setIds;
    }

    @NotNull
    public final DiagramShowcaseCategory copy(@JsonProperty("category") @NotNull String category, @JsonProperty("setIds") @NotNull List<Long> setIds) {
        Intrinsics.checkNotNullParameter(category, "category");
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        return new DiagramShowcaseCategory(category, setIds);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DiagramShowcaseCategory)) {
            return false;
        }
        DiagramShowcaseCategory diagramShowcaseCategory = (DiagramShowcaseCategory) obj;
        return Intrinsics.b(this.category, diagramShowcaseCategory.category) && Intrinsics.b(this.setIds, diagramShowcaseCategory.setIds);
    }

    @NotNull
    public final String getCategory() {
        return this.category;
    }

    @NotNull
    public final List<Long> getSetIds() {
        return this.setIds;
    }

    public int hashCode() {
        return this.setIds.hashCode() + (this.category.hashCode() * 31);
    }

    public final void setCategory(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.category = str;
    }

    public final void setSetIds(@NotNull List<Long> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.setIds = list;
    }

    @NotNull
    public String toString() {
        return "DiagramShowcaseCategory(category=" + this.category + ", setIds=" + this.setIds + ")";
    }
}
