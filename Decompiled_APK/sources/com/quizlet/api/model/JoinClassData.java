package com.quizlet.api.model;

import androidx.compose.animation.d0;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class JoinClassData {

    @JsonProperty("code")
    @NotNull
    private final String autoJoinCode;

    @JsonProperty(DBGroupMembershipFields.Names.CLASS_ID)
    private final long classId;

    @JsonProperty("level")
    private final int membershipLevel;

    @JsonProperty("userId")
    private final long userId;

    @JsonCreator
    public JoinClassData(long j, long j2, @NotNull String autoJoinCode, int i) {
        Intrinsics.checkNotNullParameter(autoJoinCode, "autoJoinCode");
        this.userId = j;
        this.classId = j2;
        this.autoJoinCode = autoJoinCode;
        this.membershipLevel = i;
    }

    public static /* synthetic */ JoinClassData copy$default(JoinClassData joinClassData, long j, long j2, String str, int i, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            j = joinClassData.userId;
        }
        long j3 = j;
        if ((i2 & 2) != 0) {
            j2 = joinClassData.classId;
        }
        long j4 = j2;
        if ((i2 & 4) != 0) {
            str = joinClassData.autoJoinCode;
        }
        String str2 = str;
        if ((i2 & 8) != 0) {
            i = joinClassData.membershipLevel;
        }
        return joinClassData.copy(j3, j4, str2, i);
    }

    public final long component1() {
        return this.userId;
    }

    public final long component2() {
        return this.classId;
    }

    @NotNull
    public final String component3() {
        return this.autoJoinCode;
    }

    public final int component4() {
        return this.membershipLevel;
    }

    @NotNull
    public final JoinClassData copy(long j, long j2, @NotNull String autoJoinCode, int i) {
        Intrinsics.checkNotNullParameter(autoJoinCode, "autoJoinCode");
        return new JoinClassData(j, j2, autoJoinCode, i);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof JoinClassData)) {
            return false;
        }
        JoinClassData joinClassData = (JoinClassData) obj;
        return this.userId == joinClassData.userId && this.classId == joinClassData.classId && Intrinsics.b(this.autoJoinCode, joinClassData.autoJoinCode) && this.membershipLevel == joinClassData.membershipLevel;
    }

    @NotNull
    public final String getAutoJoinCode() {
        return this.autoJoinCode;
    }

    public final long getClassId() {
        return this.classId;
    }

    public final int getMembershipLevel() {
        return this.membershipLevel;
    }

    public final long getUserId() {
        return this.userId;
    }

    public int hashCode() {
        return Integer.hashCode(this.membershipLevel) + d0.e(d0.d(Long.hashCode(this.userId) * 31, 31, this.classId), 31, this.autoJoinCode);
    }

    @NotNull
    public String toString() {
        long j = this.userId;
        long j2 = this.classId;
        String str = this.autoJoinCode;
        int i = this.membershipLevel;
        StringBuilder sbT = d0.t(j, "JoinClassData(userId=", ", classId=");
        sbT.append(j2);
        sbT.append(", autoJoinCode=");
        sbT.append(str);
        sbT.append(", membershipLevel=");
        sbT.append(i);
        sbT.append(")");
        return sbT.toString();
    }
}
