package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class LearnSettingsGradingUpdateData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<LearnSettingsGradingUpdateData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(16);
    public final boolean a;
    public final boolean b;
    public final boolean c;

    public LearnSettingsGradingUpdateData(boolean z, boolean z2, boolean z3) {
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    public static LearnSettingsGradingUpdateData a(LearnSettingsGradingUpdateData learnSettingsGradingUpdateData, boolean z, boolean z2, boolean z3, int i) {
        if ((i & 1) != 0) {
            z = learnSettingsGradingUpdateData.a;
        }
        if ((i & 2) != 0) {
            z2 = learnSettingsGradingUpdateData.b;
        }
        if ((i & 4) != 0) {
            z3 = learnSettingsGradingUpdateData.c;
        }
        learnSettingsGradingUpdateData.getClass();
        return new LearnSettingsGradingUpdateData(z, z2, z3);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LearnSettingsGradingUpdateData)) {
            return false;
        }
        LearnSettingsGradingUpdateData learnSettingsGradingUpdateData = (LearnSettingsGradingUpdateData) obj;
        return this.a == learnSettingsGradingUpdateData.a && this.b == learnSettingsGradingUpdateData.b && this.c == learnSettingsGradingUpdateData.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LearnSettingsGradingUpdateData(ignoreTyposEnabled=");
        sb.append(this.a);
        sb.append(", partialAnswersEnabled=");
        sb.append(this.b);
        sb.append(", smartGradingEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a ? 1 : 0);
        dest.writeInt(this.b ? 1 : 0);
        dest.writeInt(this.c ? 1 : 0);
    }
}
