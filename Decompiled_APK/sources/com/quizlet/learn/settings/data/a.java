package com.quizlet.learn.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return LearnSettingsResult.NotUpdated.a;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new LearnSettingsResult.NotUpdated[i];
    }
}
