package com.quizlet.eventlogger.features.writetransition;

import androidx.camera.camera2.internal.AbstractC0147y;
import assistantMode.refactored.a;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class WriteTransitionPayload extends StandardizedPayloadBase {

    @JsonProperty("screen_name")
    private String screenName;

    @JsonProperty("set_id")
    private String setId;

    @JsonProperty("study_mode_type")
    private Integer studyModeType;

    public WriteTransitionPayload() {
        this(null, null, null, 7, null);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WriteTransitionPayload)) {
            return false;
        }
        WriteTransitionPayload writeTransitionPayload = (WriteTransitionPayload) obj;
        return Intrinsics.b(this.setId, writeTransitionPayload.setId) && Intrinsics.b(this.screenName, writeTransitionPayload.screenName) && Intrinsics.b(this.studyModeType, writeTransitionPayload.studyModeType);
    }

    public final String getScreenName() {
        return this.screenName;
    }

    public final String getSetId() {
        return this.setId;
    }

    public final int hashCode() {
        String str = this.setId;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.screenName;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Integer num = this.studyModeType;
        return iHashCode2 + (num != null ? num.hashCode() : 0);
    }

    public final void setScreenName(String str) {
        this.screenName = str;
    }

    public final void setSetId(String str) {
        this.setId = str;
    }

    public final String toString() {
        String str = this.setId;
        String str2 = this.screenName;
        return a.l(AbstractC0147y.h("WriteTransitionPayload(setId=", str, ", screenName=", str2, ", studyModeType="), this.studyModeType, ")");
    }

    public /* synthetic */ WriteTransitionPayload(String str, String str2, Integer num, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : num);
    }

    public WriteTransitionPayload(String str, String str2, Integer num) {
        this.setId = str;
        this.screenName = str2;
        this.studyModeType = num;
    }
}
