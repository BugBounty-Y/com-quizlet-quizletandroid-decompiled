package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableQuestionSource implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableQuestionSource> CREATOR = new f(12);
    public final StudiableMetadataType a;
    public final StudiableMetadataCategory b;
    public final Integer c;

    public StudiableQuestionSource(StudiableMetadataType studiableMetadataType, StudiableMetadataCategory studiableMetadataCategory, Integer num) {
        Intrinsics.checkNotNullParameter(studiableMetadataType, "studiableMetadataType");
        this.a = studiableMetadataType;
        this.b = studiableMetadataCategory;
        this.c = num;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableQuestionSource)) {
            return false;
        }
        StudiableQuestionSource studiableQuestionSource = (StudiableQuestionSource) obj;
        return this.a == studiableQuestionSource.a && this.b == studiableQuestionSource.b && Intrinsics.b(this.c, studiableQuestionSource.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        StudiableMetadataCategory studiableMetadataCategory = this.b;
        int iHashCode2 = (iHashCode + (studiableMetadataCategory == null ? 0 : studiableMetadataCategory.hashCode())) * 31;
        Integer num = this.c;
        return iHashCode2 + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudiableQuestionSource(studiableMetadataType=");
        sb.append(this.a);
        sb.append(", studiableMetadataCategory=");
        sb.append(this.b);
        sb.append(", studiableMetadataRank=");
        return assistantMode.refactored.a.l(sb, this.c, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        this.a.writeToParcel(dest, i);
        StudiableMetadataCategory studiableMetadataCategory = this.b;
        if (studiableMetadataCategory == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableMetadataCategory.writeToParcel(dest, i);
        }
        Integer num = this.c;
        if (num == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(num.intValue());
        }
    }
}
