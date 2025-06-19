package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableDiagramImage implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableDiagramImage> CREATOR = new f(4);
    public final long a;
    public final StudiableImage b;

    public StudiableDiagramImage(long j, StudiableImage image) {
        Intrinsics.checkNotNullParameter(image, "image");
        this.a = j;
        this.b = image;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableDiagramImage)) {
            return false;
        }
        StudiableDiagramImage studiableDiagramImage = (StudiableDiagramImage) obj;
        return this.a == studiableDiagramImage.a && Intrinsics.b(this.b, studiableDiagramImage.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudiableDiagramImage(id=" + this.a + ", image=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a);
        this.b.writeToParcel(dest, i);
    }
}
