package com.quizlet.explanations.textbook.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class r implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new TextbookSetUpState.Exercise(parcel.readString());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new TextbookSetUpState.Exercise[i];
    }
}
