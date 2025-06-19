package com.quizlet.eventlogger.features.flashcards;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsEventPayload extends StandardizedPayloadBase {

    @JsonProperty("starred_only")
    private Boolean isStarredOnly;

    @JsonProperty("next_action")
    private String nextAction;

    @JsonProperty("screen")
    private String screenName;

    @JsonProperty("flashcard_mode")
    private String sortingMode;

    public FlashcardsEventPayload() {
        this(null, null, null, null, 15, null);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsEventPayload)) {
            return false;
        }
        FlashcardsEventPayload flashcardsEventPayload = (FlashcardsEventPayload) obj;
        return Intrinsics.b(this.sortingMode, flashcardsEventPayload.sortingMode) && Intrinsics.b(this.screenName, flashcardsEventPayload.screenName) && Intrinsics.b(this.nextAction, flashcardsEventPayload.nextAction) && Intrinsics.b(this.isStarredOnly, flashcardsEventPayload.isStarredOnly);
    }

    public final String getNextAction() {
        return this.nextAction;
    }

    public final String getScreenName() {
        return this.screenName;
    }

    public final String getSortingMode() {
        return this.sortingMode;
    }

    public final int hashCode() {
        String str = this.sortingMode;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.screenName;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.nextAction;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Boolean bool = this.isStarredOnly;
        return iHashCode3 + (bool != null ? bool.hashCode() : 0);
    }

    public final void setNextAction(String str) {
        this.nextAction = str;
    }

    public final void setScreenName(String str) {
        this.screenName = str;
    }

    public final void setSortingMode(String str) {
        this.sortingMode = str;
    }

    public final void setStarredOnly(Boolean bool) {
        this.isStarredOnly = bool;
    }

    public final String toString() {
        String str = this.sortingMode;
        String str2 = this.screenName;
        String str3 = this.nextAction;
        Boolean bool = this.isStarredOnly;
        StringBuilder sbH = AbstractC0147y.h("FlashcardsEventPayload(sortingMode=", str, ", screenName=", str2, ", nextAction=");
        sbH.append(str3);
        sbH.append(", isStarredOnly=");
        sbH.append(bool);
        sbH.append(")");
        return sbH.toString();
    }

    public /* synthetic */ FlashcardsEventPayload(String str, String str2, String str3, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, (i & 8) != 0 ? null : bool);
    }

    public FlashcardsEventPayload(String str, String str2, String str3, Boolean bool) {
        this.sortingMode = str;
        this.screenName = str2;
        this.nextAction = str3;
        this.isStarredOnly = bool;
    }
}
