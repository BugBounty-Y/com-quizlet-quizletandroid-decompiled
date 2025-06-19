package com.quizlet.features.questionnaire.navigation;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class Progress implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<Progress> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(8);
    public final int a;
    public final int b;

    public Progress(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Progress)) {
            return false;
        }
        Progress progress = (Progress) obj;
        return this.a == progress.a && this.b == progress.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Progress(current=");
        sb.append(this.a);
        sb.append(", total=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
        dest.writeInt(this.b);
    }
}
