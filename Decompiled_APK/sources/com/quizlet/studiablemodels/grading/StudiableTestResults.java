package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableTestResults implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableTestResults> CREATOR = new e(0);
    public final double a;
    public final ArrayList b;
    public final StudiableMeteringData c;

    public StudiableTestResults(double d, ArrayList gradedAnswers, StudiableMeteringData studiableMeteringData) {
        Intrinsics.checkNotNullParameter(gradedAnswers, "gradedAnswers");
        this.a = d;
        this.b = gradedAnswers;
        this.c = studiableMeteringData;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableTestResults)) {
            return false;
        }
        StudiableTestResults studiableTestResults = (StudiableTestResults) obj;
        return Double.compare(this.a, studiableTestResults.a) == 0 && this.b.equals(studiableTestResults.b) && Intrinsics.b(this.c, studiableTestResults.c);
    }

    public final int hashCode() {
        int iH = d0.h(this.b, Double.hashCode(this.a) * 31, 31);
        StudiableMeteringData studiableMeteringData = this.c;
        return iH + (studiableMeteringData == null ? 0 : studiableMeteringData.hashCode());
    }

    public final String toString() {
        return "StudiableTestResults(percentage=" + this.a + ", gradedAnswers=" + this.b + ", studiableMeteringData=" + this.c + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeDouble(this.a);
        ArrayList arrayList = this.b;
        dest.writeInt(arrayList.size());
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            ((StudiableQuestionGradedAnswer) it2.next()).writeToParcel(dest, i);
        }
        StudiableMeteringData studiableMeteringData = this.c;
        if (studiableMeteringData == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableMeteringData.writeToParcel(dest, i);
        }
    }
}
