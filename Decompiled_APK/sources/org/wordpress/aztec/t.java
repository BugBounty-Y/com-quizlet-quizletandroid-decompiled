package org.wordpress.aztec;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;

/* loaded from: classes3.dex */
public final class t implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "source");
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        AztecText.SavedState savedState = new AztecText.SavedState(parcel);
        savedState.a = new Bundle();
        Bundle bundle = parcel.readBundle(AztecText.SavedState.class.getClassLoader());
        if (bundle != null) {
            savedState.a = bundle;
        }
        return savedState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new AztecText.SavedState[i];
    }
}
