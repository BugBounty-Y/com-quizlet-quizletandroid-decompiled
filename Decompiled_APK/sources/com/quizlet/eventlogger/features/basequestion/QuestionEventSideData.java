package com.quizlet.eventlogger.features.basequestion;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.O1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionEventSideData {
    private final boolean hasAudio;
    private final boolean hasImage;
    private final boolean hasText;

    @NotNull
    private final O1 side;

    public QuestionEventSideData(@NotNull O1 side, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(side, "side");
        this.side = side;
        this.hasText = z;
        this.hasImage = z2;
        this.hasAudio = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionEventSideData)) {
            return false;
        }
        QuestionEventSideData questionEventSideData = (QuestionEventSideData) obj;
        return this.side == questionEventSideData.side && this.hasText == questionEventSideData.hasText && this.hasImage == questionEventSideData.hasImage && this.hasAudio == questionEventSideData.hasAudio;
    }

    public final boolean getHasAudio() {
        return this.hasAudio;
    }

    public final boolean getHasImage() {
        return this.hasImage;
    }

    public final boolean getHasText() {
        return this.hasText;
    }

    @NotNull
    public final O1 getSide() {
        return this.side;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.hasAudio) + d0.g(d0.g(this.side.hashCode() * 31, 31, this.hasText), 31, this.hasImage);
    }

    public final String toString() {
        return "QuestionEventSideData(side=" + this.side + ", hasText=" + this.hasText + ", hasImage=" + this.hasImage + ", hasAudio=" + this.hasAudio + ")";
    }
}
