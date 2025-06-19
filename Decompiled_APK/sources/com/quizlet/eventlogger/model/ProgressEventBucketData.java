package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class ProgressEventBucketData {

    @JsonProperty("percentage")
    private final int percentage;

    @JsonProperty(DBStudySetFields.Names.NUM_TERMS)
    private final int termCount;

    public ProgressEventBucketData(int i, int i2) {
        this.percentage = i;
        this.termCount = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ProgressEventBucketData)) {
            return false;
        }
        ProgressEventBucketData progressEventBucketData = (ProgressEventBucketData) obj;
        return this.percentage == progressEventBucketData.percentage && this.termCount == progressEventBucketData.termCount;
    }

    public final int getPercentage() {
        return this.percentage;
    }

    public final int getTermCount() {
        return this.termCount;
    }

    public final int hashCode() {
        return Integer.hashCode(this.termCount) + (Integer.hashCode(this.percentage) * 31);
    }

    public final String toString() {
        return a.j("ProgressEventBucketData(percentage=", this.percentage, ", termCount=", ")", this.termCount);
    }
}
