package com.quizlet.api.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class TextAnnotations {

    @NotNull
    private final Bounds boundingPoly;

    @NotNull
    private final String description;
    private final String locale;

    @JsonCreator
    public TextAnnotations(@JsonProperty("locale") String str, @JsonProperty(OTUXParamsKeys.OT_UX_DESCRIPTION) @NotNull String description, @JsonProperty("boundingPoly") @NotNull Bounds boundingPoly) {
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(boundingPoly, "boundingPoly");
        this.locale = str;
        this.description = description;
        this.boundingPoly = boundingPoly;
    }

    public static /* synthetic */ TextAnnotations copy$default(TextAnnotations textAnnotations, String str, String str2, Bounds bounds, int i, Object obj) {
        if ((i & 1) != 0) {
            str = textAnnotations.locale;
        }
        if ((i & 2) != 0) {
            str2 = textAnnotations.description;
        }
        if ((i & 4) != 0) {
            bounds = textAnnotations.boundingPoly;
        }
        return textAnnotations.copy(str, str2, bounds);
    }

    public final String component1() {
        return this.locale;
    }

    @NotNull
    public final String component2() {
        return this.description;
    }

    @NotNull
    public final Bounds component3() {
        return this.boundingPoly;
    }

    @NotNull
    public final TextAnnotations copy(@JsonProperty("locale") String str, @JsonProperty(OTUXParamsKeys.OT_UX_DESCRIPTION) @NotNull String description, @JsonProperty("boundingPoly") @NotNull Bounds boundingPoly) {
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(boundingPoly, "boundingPoly");
        return new TextAnnotations(str, description, boundingPoly);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TextAnnotations)) {
            return false;
        }
        TextAnnotations textAnnotations = (TextAnnotations) obj;
        return Intrinsics.b(this.locale, textAnnotations.locale) && Intrinsics.b(this.description, textAnnotations.description) && Intrinsics.b(this.boundingPoly, textAnnotations.boundingPoly);
    }

    @NotNull
    public final Bounds getBoundingPoly() {
        return this.boundingPoly;
    }

    @NotNull
    public final String getDescription() {
        return this.description;
    }

    public final String getLocale() {
        return this.locale;
    }

    public int hashCode() {
        String str = this.locale;
        return this.boundingPoly.hashCode() + d0.e((str == null ? 0 : str.hashCode()) * 31, 31, this.description);
    }

    @NotNull
    public String toString() {
        String str = this.locale;
        String str2 = this.description;
        Bounds bounds = this.boundingPoly;
        StringBuilder sbH = AbstractC0147y.h("TextAnnotations(locale=", str, ", description=", str2, ", boundingPoly=");
        sbH.append(bounds);
        sbH.append(")");
        return sbH.toString();
    }
}
