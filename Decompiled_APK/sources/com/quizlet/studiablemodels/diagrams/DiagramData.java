package com.quizlet.studiablemodels.diagrams;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBTerm;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class DiagramData {

    @NotNull
    private static final a Names = new a();

    @JsonIgnore
    @NotNull
    private final DBImage diagramImage;

    @JsonIgnore
    @NotNull
    private final Map<String, DBDiagramShape> diagramShapesByTermId;

    @JsonIgnore
    private final long setId;

    @JsonIgnore
    @NotNull
    private final Map<String, DBTerm> termsByTermId;

    @Metadata
    public static final class Builder {

        @NotNull
        private List<? extends DBDiagramShape> diagramShapes = K.a;
        private DBImage image;
        private long setId;

        public final DiagramData a() {
            List<? extends DBDiagramShape> list = this.diagramShapes;
            ArrayList arrayList = new ArrayList(C.q(list, 10));
            for (DBDiagramShape dBDiagramShape : list) {
                arrayList.add(new Pair(String.valueOf(dBDiagramShape.getTermId()), dBDiagramShape));
            }
            Pair[] pairArr = (Pair[]) arrayList.toArray(new Pair[0]);
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            for (Pair pair : pairArr) {
                linkedHashMap.put(pair.a, null);
            }
            long j = this.setId;
            HashMap mapE = V.e((Pair[]) Arrays.copyOf(pairArr, pairArr.length));
            DBImage dBImage = this.image;
            if (dBImage != null) {
                return new DiagramData(linkedHashMap, mapE, dBImage, j);
            }
            throw new NullPointerException("you need to set an image for DiagramData");
        }

        public final void b(List diagramShapes) {
            Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
            this.diagramShapes = diagramShapes;
        }

        public final void c(DBImage image) {
            Intrinsics.checkNotNullParameter(image, "image");
            this.image = image;
        }

        public final void d(long j) {
            this.setId = j;
        }
    }

    public DiagramData(LinkedHashMap termsByTermId, HashMap diagramShapesByTermId, DBImage diagramImage, long j) {
        Intrinsics.checkNotNullParameter(termsByTermId, "termsByTermId");
        Intrinsics.checkNotNullParameter(diagramShapesByTermId, "diagramShapesByTermId");
        Intrinsics.checkNotNullParameter(diagramImage, "diagramImage");
        this.termsByTermId = termsByTermId;
        this.diagramShapesByTermId = diagramShapesByTermId;
        this.diagramImage = diagramImage;
        this.setId = j;
    }

    public final Builder a() {
        Builder builder = new Builder();
        builder.d(this.setId);
        builder.b(CollectionsKt.w0(this.diagramShapesByTermId.values()));
        builder.c(this.diagramImage);
        return builder;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DiagramData)) {
            return false;
        }
        DiagramData diagramData = (DiagramData) obj;
        return Intrinsics.b(this.termsByTermId, diagramData.termsByTermId) && Intrinsics.b(this.diagramShapesByTermId, diagramData.diagramShapesByTermId) && Intrinsics.b(this.diagramImage, diagramData.diagramImage) && this.setId == diagramData.setId;
    }

    @JsonProperty("diagramImage")
    @NotNull
    public final DBImage getDiagramImage() {
        return this.diagramImage;
    }

    @JsonProperty("diagramShapesByTermId")
    @NotNull
    public final Map<String, DBDiagramShape> getDiagramShapesByTermId() {
        return this.diagramShapesByTermId;
    }

    @JsonIgnore
    public final long getSetId() {
        return this.setId;
    }

    @JsonProperty("termsByTermId")
    @NotNull
    public final Map<String, DBTerm> getTermsByTermId() {
        return this.termsByTermId;
    }

    public final int hashCode() {
        return Long.hashCode(this.setId) + ((this.diagramImage.hashCode() + assistantMode.refactored.a.d(this.termsByTermId.hashCode() * 31, 31, this.diagramShapesByTermId)) * 31);
    }

    public final String toString() {
        return "DiagramData(termsByTermId=" + this.termsByTermId + ", diagramShapesByTermId=" + this.diagramShapesByTermId + ", diagramImage=" + this.diagramImage + ", setId=" + this.setId + ")";
    }
}
