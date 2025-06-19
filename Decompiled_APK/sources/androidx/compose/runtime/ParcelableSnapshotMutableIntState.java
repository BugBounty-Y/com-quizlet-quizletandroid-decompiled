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
final class ParcelableSnapshotMutableIntState extends H0 implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<ParcelableSnapshotMutableIntState> CREATOR = new C0793e0(1);

    public ParcelableSnapshotMutableIntState(int i) {
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        G0 g0 = new G0(i, hVarK.g());
        if (!(hVarK instanceof C0823c)) {
            g0.b = new G0(i, 1);
        }
        this.b = g0;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(i());
    }
}
