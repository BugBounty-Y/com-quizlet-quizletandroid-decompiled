package androidx.compose.runtime;

import android.os.Parcel;
import android.os.Parcelable;

/* renamed from: androidx.compose.runtime.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0793e0 implements Parcelable.Creator {
    public final /* synthetic */ int a;

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                return new ParcelableSnapshotMutableFloatState(parcel.readFloat());
            case 1:
                return new ParcelableSnapshotMutableIntState(parcel.readInt());
            default:
                return new ParcelableSnapshotMutableLongState(parcel.readLong());
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new ParcelableSnapshotMutableFloatState[i];
            case 1:
                return new ParcelableSnapshotMutableIntState[i];
            default:
                return new ParcelableSnapshotMutableLongState[i];
        }
    }
}
