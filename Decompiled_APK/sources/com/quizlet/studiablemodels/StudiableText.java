package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.M;
import com.quizlet.generated.enums.N;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableText implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableText> CREATOR = new f(16);
    public final String a;
    public final String b;
    public final String c;

    public StudiableText(String plainText, String str, String str2) {
        Intrinsics.checkNotNullParameter(plainText, "plainText");
        this.a = plainText;
        this.b = str;
        this.c = str2;
        M m = N.Companion;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableText)) {
            return false;
        }
        StudiableText studiableText = (StudiableText) obj;
        return Intrinsics.b(this.a, studiableText.a) && Intrinsics.b(this.b, studiableText.b) && Intrinsics.b(this.c, studiableText.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return iHashCode2 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudiableText(plainText=");
        sb.append(this.a);
        sb.append(", languageCode=");
        sb.append(this.b);
        sb.append(", richText=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeString(this.c);
    }
}
