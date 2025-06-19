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
final class ParcelableSnapshotMutableFloatState extends F0 implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<ParcelableSnapshotMutableFloatState> CREATOR = new C0793e0(0);

    public ParcelableSnapshotMutableFloatState(float f) {
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        E0 e0 = new E0(hVarK.g(), f);
        if (!(hVarK instanceof C0823c)) {
            e0.b = new E0(1, f);
        }
        this.b = e0;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeFloat(i());
    }
}
