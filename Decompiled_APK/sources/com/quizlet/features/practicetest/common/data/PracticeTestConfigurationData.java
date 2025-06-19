package com.quizlet.features.practicetest.common.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestConfigurationData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<PracticeTestConfigurationData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(7);
    public final int a;
    public final boolean b;
    public final boolean c;

    public PracticeTestConfigurationData(int i, boolean z, boolean z2) {
        this.a = i;
        this.b = z;
        this.c = z2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestConfigurationData)) {
            return false;
        }
        PracticeTestConfigurationData practiceTestConfigurationData = (PracticeTestConfigurationData) obj;
        return this.a == practiceTestConfigurationData.a && this.b == practiceTestConfigurationData.b && this.c == practiceTestConfigurationData.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Integer.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestConfigurationData(questionCount=");
        sb.append(this.a);
        sb.append(", isMcqOn=");
        sb.append(this.b);
        sb.append(", isWrittenOn=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
        dest.writeInt(this.b ? 1 : 0);
        dest.writeInt(this.c ? 1 : 0);
    }
}
