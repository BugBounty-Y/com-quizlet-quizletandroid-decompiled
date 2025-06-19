package com.quizlet.api.model;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBStudySet;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DiagramShowcaseModels {

    @NotNull
    private List<? extends DBImageRef> imageRefs;

    @NotNull
    private List<? extends DBImage> images;

    @NotNull
    private List<? extends DBStudySet> studySets;

    @JsonCreator
    public DiagramShowcaseModels() {
        this(null, null, null, 7, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ DiagramShowcaseModels copy$default(DiagramShowcaseModels diagramShowcaseModels, List list, List list2, List list3, int i, Object obj) {
        if ((i & 1) != 0) {
            list = diagramShowcaseModels.imageRefs;
        }
        if ((i & 2) != 0) {
            list2 = diagramShowcaseModels.images;
        }
        if ((i & 4) != 0) {
            list3 = diagramShowcaseModels.studySets;
        }
        return diagramShowcaseModels.copy(list, list2, list3);
    }

    @NotNull
    public final List<DBImageRef> component1() {
        return this.imageRefs;
    }

    @NotNull
    public final List<DBImage> component2() {
        return this.images;
    }

    @NotNull
    public final List<DBStudySet> component3() {
        return this.studySets;
    }

    @NotNull
    public final DiagramShowcaseModels copy(@JsonProperty(DBImageRef.TABLE_NAME) @NotNull List<? extends DBImageRef> imageRefs, @JsonProperty("image") @NotNull List<? extends DBImage> images, @JsonProperty("set") @NotNull List<? extends DBStudySet> studySets) {
        Intrinsics.checkNotNullParameter(imageRefs, "imageRefs");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(studySets, "studySets");
        return new DiagramShowcaseModels(imageRefs, images, studySets);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DiagramShowcaseModels)) {
            return false;
        }
        DiagramShowcaseModels diagramShowcaseModels = (DiagramShowcaseModels) obj;
        return Intrinsics.b(this.imageRefs, diagramShowcaseModels.imageRefs) && Intrinsics.b(this.images, diagramShowcaseModels.images) && Intrinsics.b(this.studySets, diagramShowcaseModels.studySets);
    }

    @NotNull
    public final List<DBImageRef> getImageRefs() {
        return this.imageRefs;
    }

    @NotNull
    public final List<DBImage> getImages() {
        return this.images;
    }

    @NotNull
    public final List<DBStudySet> getStudySets() {
        return this.studySets;
    }

    public int hashCode() {
        return this.studySets.hashCode() + d0.f(this.imageRefs.hashCode() * 31, 31, this.images);
    }

    public final void setImageRefs(@NotNull List<? extends DBImageRef> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.imageRefs = list;
    }

    public final void setImages(@NotNull List<? extends DBImage> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.images = list;
    }

    public final void setStudySets(@NotNull List<? extends DBStudySet> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.studySets = list;
    }

    @NotNull
    public String toString() {
        List<? extends DBImageRef> list = this.imageRefs;
        List<? extends DBImage> list2 = this.images;
        List<? extends DBStudySet> list3 = this.studySets;
        StringBuilder sb = new StringBuilder("DiagramShowcaseModels(imageRefs=");
        sb.append(list);
        sb.append(", images=");
        sb.append(list2);
        sb.append(", studySets=");
        return a.n(")", sb, list3);
    }

    @JsonCreator
    public DiagramShowcaseModels(@JsonProperty(DBImageRef.TABLE_NAME) @NotNull List<? extends DBImageRef> imageRefs, @JsonProperty("image") @NotNull List<? extends DBImage> images, @JsonProperty("set") @NotNull List<? extends DBStudySet> studySets) {
        Intrinsics.checkNotNullParameter(imageRefs, "imageRefs");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(studySets, "studySets");
        this.imageRefs = imageRefs;
        this.images = images;
        this.studySets = studySets;
    }

    public DiagramShowcaseModels(List list, List list2, List list3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list, (i & 2) != 0 ? K.a : list2, (i & 4) != 0 ? K.a : list3);
    }
}
