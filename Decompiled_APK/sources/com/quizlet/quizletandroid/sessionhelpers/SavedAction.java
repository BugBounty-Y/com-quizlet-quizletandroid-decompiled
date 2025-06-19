package com.quizlet.quizletandroid.sessionhelpers;

import android.os.Parcel;
import android.os.Parcelable;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SavedAction implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<SavedAction> CREATOR = new f(12);
    public final String a;
    public final Long b;
    public final Long c;
    public final Long d;

    public SavedAction(String action, Long l, Long l2) {
        Intrinsics.checkNotNullParameter(action, "action");
        this.a = action;
        this.b = l;
        this.c = l2;
        this.d = (l2 == null || l2.longValue() <= 0) ? null : l2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SavedAction)) {
            return false;
        }
        SavedAction savedAction = (SavedAction) obj;
        return Intrinsics.b(this.a, savedAction.a) && Intrinsics.b(this.b, savedAction.b) && Intrinsics.b(this.c, savedAction.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Long l = this.b;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.c;
        return iHashCode2 + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "SavedAction(action=" + this.a + ", localId=" + this.b + ", _serverId=" + this.c + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        Long l = this.b;
        if (l == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l.longValue());
        }
        Long l2 = this.c;
        if (l2 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l2.longValue());
        }
    }
}
