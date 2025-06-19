package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class LearnSettingsIntentData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<LearnSettingsIntentData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(14);
    public final String a;
    public final StudyableModelData b;
    public final long c;
    public final boolean d;
    public final String e;
    public final int f;

    public LearnSettingsIntentData(int i, long j, StudyableModelData studyableModelData, String studySessionId, String screenName, boolean z) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        this.a = studySessionId;
        this.b = studyableModelData;
        this.c = j;
        this.d = z;
        this.e = screenName;
        this.f = i;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LearnSettingsIntentData)) {
            return false;
        }
        LearnSettingsIntentData learnSettingsIntentData = (LearnSettingsIntentData) obj;
        return Intrinsics.b(this.a, learnSettingsIntentData.a) && Intrinsics.b(this.b, learnSettingsIntentData.b) && this.c == learnSettingsIntentData.c && this.d == learnSettingsIntentData.d && Intrinsics.b(this.e, learnSettingsIntentData.e) && this.f == learnSettingsIntentData.f;
    }

    public final int hashCode() {
        return Integer.hashCode(this.f) + d0.e(d0.g(d0.d((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LearnSettingsIntentData(studySessionId=");
        sb.append(this.a);
        sb.append(", studyableModelData=");
        sb.append(this.b);
        sb.append(", studyableModelLocalId=");
        sb.append(this.c);
        sb.append(", selectedTermsOnly=");
        sb.append(this.d);
        sb.append(", screenName=");
        sb.append(this.e);
        sb.append(", navigationSource=");
        return android.support.v4.media.session.a.r(sb, this.f, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeParcelable(this.b, i);
        dest.writeLong(this.c);
        dest.writeInt(this.d ? 1 : 0);
        dest.writeString(this.e);
        dest.writeInt(this.f);
    }
}
