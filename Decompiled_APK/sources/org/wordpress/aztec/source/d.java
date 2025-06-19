package org.wordpress.aztec.source;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.source.SourceViewEditText;

/* loaded from: classes3.dex */
public final class d implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "source");
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        SourceViewEditText.SavedState savedState = new SourceViewEditText.SavedState(parcel);
        savedState.a = new Bundle();
        Bundle bundle = parcel.readBundle(SourceViewEditText.SavedState.class.getClassLoader());
        if (bundle != null) {
            savedState.a = bundle;
        }
        return savedState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new SourceViewEditText.SavedState[i];
    }
}
