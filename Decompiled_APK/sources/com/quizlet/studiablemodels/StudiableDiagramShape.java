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
public final class StudiableDiagramShape implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableDiagramShape> CREATOR = new f(5);
    public final String a;

    public StudiableDiagramShape(String shape) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.a = shape;
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
        return (obj instanceof StudiableDiagramShape) && Intrinsics.b(this.a, ((StudiableDiagramShape) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StudiableDiagramShape(shape="), this.a, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
    }
}
