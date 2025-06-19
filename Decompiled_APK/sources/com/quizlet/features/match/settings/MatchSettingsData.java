package com.quizlet.features.match.settings;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MatchSettingsData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<MatchSettingsData> CREATOR = new f(6);
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;

    public MatchSettingsData(boolean z, boolean z2, boolean z3, boolean z4) {
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MatchSettingsData)) {
            return false;
        }
        MatchSettingsData matchSettingsData = (MatchSettingsData) obj;
        return this.a == matchSettingsData.a && this.b == matchSettingsData.b && this.c == matchSettingsData.c && this.d == matchSettingsData.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "MatchSettingsData(inSelectedTermsMode=" + this.a + ", shouldMatchTerm=" + this.b + ", shouldMatchDefinition=" + this.c + ", shouldMatchLocation=" + this.d + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a ? 1 : 0);
        dest.writeInt(this.b ? 1 : 0);
        dest.writeInt(this.c ? 1 : 0);
        dest.writeInt(this.d ? 1 : 0);
    }
}
