package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Bounds {

    @NotNull
    private final List<Point> vertices;

    @JsonCreator
    public Bounds(@JsonProperty("vertices") @NotNull List<Point> vertices) {
        Intrinsics.checkNotNullParameter(vertices, "vertices");
        this.vertices = vertices;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ Bounds copy$default(Bounds bounds, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            list = bounds.vertices;
        }
        return bounds.copy(list);
    }

    @NotNull
    public final List<Point> component1() {
        return this.vertices;
    }

    @NotNull
    public final Bounds copy(@JsonProperty("vertices") @NotNull List<Point> vertices) {
        Intrinsics.checkNotNullParameter(vertices, "vertices");
        return new Bounds(vertices);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof Bounds) && Intrinsics.b(this.vertices, ((Bounds) obj).vertices);
    }

    @NotNull
    public final List<Point> getVertices() {
        return this.vertices;
    }

    public int hashCode() {
        return this.vertices.hashCode();
    }

    @NotNull
    public String toString() {
        return "Bounds(vertices=" + this.vertices + ")";
    }
}
