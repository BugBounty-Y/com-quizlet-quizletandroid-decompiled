package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4508o1;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PLongtextGradingResult implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<PLongtextGradingResult> CREATOR = new f(25);
    public final EnumC4508o1 a;
    public final double b;
    public final String c;
    public final Double d;
    public final String e;

    public PLongtextGradingResult(EnumC4508o1 grade, double d, String model, Double d2, String str) {
        Intrinsics.checkNotNullParameter(grade, "grade");
        Intrinsics.checkNotNullParameter(model, "model");
        this.a = grade;
        this.b = d;
        this.c = model;
        this.d = d2;
        this.e = str;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PLongtextGradingResult)) {
            return false;
        }
        PLongtextGradingResult pLongtextGradingResult = (PLongtextGradingResult) obj;
        return this.a == pLongtextGradingResult.a && Double.compare(this.b, pLongtextGradingResult.b) == 0 && Intrinsics.b(this.c, pLongtextGradingResult.c) && Intrinsics.b(this.d, pLongtextGradingResult.d) && Intrinsics.b(this.e, pLongtextGradingResult.e);
    }

    public final int hashCode() {
        int iE = d0.e(d0.a(this.b, this.a.hashCode() * 31, 31), 31, this.c);
        Double d = this.d;
        int iHashCode = (iE + (d == null ? 0 : d.hashCode())) * 31;
        String str = this.e;
        return iHashCode + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PLongtextGradingResult(grade=");
        sb.append(this.a);
        sb.append(", score=");
        sb.append(this.b);
        sb.append(", model=");
        sb.append(this.c);
        sb.append(", cnnScore=");
        sb.append(this.d);
        sb.append(", missing=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a.name());
        dest.writeDouble(this.b);
        dest.writeString(this.c);
        Double d = this.d;
        if (d == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeDouble(d.doubleValue());
        }
        dest.writeString(this.e);
    }
}
