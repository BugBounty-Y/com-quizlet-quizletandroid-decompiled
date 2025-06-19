package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PLocalGradedAnswerMetadata extends PGradedAnswerMetadata {
    public static final PLocalGradedAnswerMetadata b = new PLocalGradedAnswerMetadata(false);

    @NotNull
    public static final Parcelable.Creator<PLocalGradedAnswerMetadata> CREATOR = new f(24);

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(1);
    }
}
