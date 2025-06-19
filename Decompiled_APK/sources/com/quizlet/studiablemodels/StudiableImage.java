package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.M;
import com.quizlet.generated.enums.N;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableImage implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableImage> CREATOR = new f(6);
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final int e;

    public StudiableImage(String str, int i, String str2, String str3, int i2) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = i;
        this.e = i2;
        M m = N.Companion;
    }

    public final String a() {
        String str = this.b;
        return str == null ? this.a : str;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableImage)) {
            return false;
        }
        StudiableImage studiableImage = (StudiableImage) obj;
        return Intrinsics.b(this.a, studiableImage.a) && Intrinsics.b(this.b, studiableImage.b) && Intrinsics.b(this.c, studiableImage.c) && this.d == studiableImage.d && this.e == studiableImage.e;
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.c;
        return Integer.hashCode(this.e) + d0.b(this.d, (iHashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudiableImage(smallUrl=");
        sb.append(this.a);
        sb.append(", mediumUrl=");
        sb.append(this.b);
        sb.append(", largeUrl=");
        sb.append(this.c);
        sb.append(", width=");
        sb.append(this.d);
        sb.append(", height=");
        return android.support.v4.media.session.a.r(sb, this.e, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeString(this.c);
        dest.writeInt(this.d);
        dest.writeInt(this.e);
    }
}
