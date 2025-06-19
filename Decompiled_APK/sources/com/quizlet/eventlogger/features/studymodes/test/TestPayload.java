package com.quizlet.eventlogger.features.studymodes.test;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class TestPayload extends StandardizedPayloadBase {

    @Metadata
    public static final class CardAudio extends TestPayload {

        @JsonProperty("set_id")
        @NotNull
        private final String setId;

        @JsonProperty("term_side")
        private String termSide;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public CardAudio(@NotNull String setId, String str) {
            super(null);
            Intrinsics.checkNotNullParameter(setId, "setId");
            this.setId = setId;
            this.termSide = str;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof CardAudio)) {
                return false;
            }
            CardAudio cardAudio = (CardAudio) obj;
            return Intrinsics.b(this.setId, cardAudio.setId) && Intrinsics.b(this.termSide, cardAudio.termSide);
        }

        @NotNull
        public final String getSetId() {
            return this.setId;
        }

        public final String getTermSide() {
            return this.termSide;
        }

        public final int hashCode() {
            int iHashCode = this.setId.hashCode() * 31;
            String str = this.termSide;
            return iHashCode + (str == null ? 0 : str.hashCode());
        }

        public final void setTermSide(String str) {
            this.termSide = str;
        }

        public final String toString() {
            return AbstractC0147y.e("CardAudio(setId=", this.setId, ", termSide=", this.termSide, ")");
        }
    }

    @Metadata
    public static final class Click extends TestPayload {

        @JsonProperty("set_id")
        @NotNull
        private final String setId;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public Click(@NotNull String setId) {
            super(null);
            Intrinsics.checkNotNullParameter(setId, "setId");
            this.setId = setId;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Click) && Intrinsics.b(this.setId, ((Click) obj).setId);
        }

        @NotNull
        public final String getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            return this.setId.hashCode();
        }

        public final String toString() {
            return a.B("Click(setId=", this.setId, ")");
        }
    }

    public /* synthetic */ TestPayload(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    private TestPayload() {
    }
}
