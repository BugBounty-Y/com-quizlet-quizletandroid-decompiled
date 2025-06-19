package com.quizlet.features.infra.studysetting.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GradingSettingsValues implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<GradingSettingsValues> CREATOR = new a(0);
    public final boolean a;
    public final boolean b;
    public final boolean c;

    public GradingSettingsValues(boolean z, boolean z2, boolean z3) {
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GradingSettingsValues)) {
            return false;
        }
        GradingSettingsValues gradingSettingsValues = (GradingSettingsValues) obj;
        return this.a == gradingSettingsValues.a && this.b == gradingSettingsValues.b && this.c == gradingSettingsValues.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GradingSettingsValues(isPartialAnswersEnabled=");
        sb.append(this.a);
        sb.append(", isSmartGradingEnabled=");
        sb.append(this.b);
        sb.append(", isTypoCorrectionEnabled=");
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
