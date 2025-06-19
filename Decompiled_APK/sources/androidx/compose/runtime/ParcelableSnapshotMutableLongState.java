package androidx.compose.runtime;

import android.annotation.SuppressLint;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.runtime.snapshots.C0823c;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
@SuppressLint({"BanParcelableUsage"})
/* loaded from: classes.dex */
final class ParcelableSnapshotMutableLongState extends J0 implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<ParcelableSnapshotMutableLongState> CREATOR = new C0793e0(2);

    public ParcelableSnapshotMutableLongState(long j) {
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        I0 i0 = new I0(hVarK.g(), j);
        if (!(hVarK instanceof C0823c)) {
            i0.b = new I0(1, j);
        }
        this.b = i0;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeLong(i());
    }
}
