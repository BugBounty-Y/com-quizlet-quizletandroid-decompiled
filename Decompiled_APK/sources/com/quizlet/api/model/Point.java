package com.quizlet.api.model;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Point {
    private final int x;
    private final int y;

    @JsonCreator
    public Point(@JsonProperty("x") int i, @JsonProperty("y") int i2) {
        this.x = i;
        this.y = i2;
    }

    public static /* synthetic */ Point copy$default(Point point, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = point.x;
        }
        if ((i3 & 2) != 0) {
            i2 = point.y;
        }
        return point.copy(i, i2);
    }

    public final int component1() {
        return this.x;
    }

    public final int component2() {
        return this.y;
    }

    @NotNull
    public final Point copy(@JsonProperty("x") int i, @JsonProperty("y") int i2) {
        return new Point(i, i2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Point)) {
            return false;
        }
        Point point = (Point) obj;
        return this.x == point.x && this.y == point.y;
    }

    public final int getX() {
        return this.x;
    }

    public final int getY() {
        return this.y;
    }

    public int hashCode() {
        return Integer.hashCode(this.y) + (Integer.hashCode(this.x) * 31);
    }

    @NotNull
    public String toString() {
        return a.j("Point(x=", this.x, ", y=", ")", this.y);
    }
}
