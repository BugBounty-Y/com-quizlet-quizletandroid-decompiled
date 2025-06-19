package com.airbnb.lottie;

import android.os.Parcel;
import android.os.Parcelable;
import com.airbnb.lottie.LottieAnimationView;

/* renamed from: com.airbnb.lottie.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1465e implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        LottieAnimationView.SavedState savedState = new LottieAnimationView.SavedState(parcel);
        savedState.a = parcel.readString();
        savedState.c = parcel.readFloat();
        savedState.d = parcel.readInt() == 1;
        savedState.e = parcel.readString();
        savedState.f = parcel.readInt();
        savedState.g = parcel.readInt();
        return savedState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new LottieAnimationView.SavedState[i];
    }
}
