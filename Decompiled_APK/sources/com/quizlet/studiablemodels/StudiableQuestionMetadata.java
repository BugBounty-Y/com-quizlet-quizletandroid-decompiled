package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.enums.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableQuestionMetadata implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableQuestionMetadata> CREATOR = new f(11);
    public final k a;
    public final long b;
    public final m c;
    public final m d;
    public final StudiableDiagramImage e;
    public final StudiableQuestionSource f;

    public StudiableQuestionMetadata(k questionType, long j, m promptSide, m answerSide, StudiableDiagramImage studiableDiagramImage, StudiableQuestionSource studiableQuestionSource) {
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        this.a = questionType;
        this.b = j;
        this.c = promptSide;
        this.d = answerSide;
        this.e = studiableDiagramImage;
        this.f = studiableQuestionSource;
    }

    public final boolean a() {
        return this.c == m.d;
    }

    public final boolean b() {
        return this.d == m.d || a();
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableQuestionMetadata)) {
            return false;
        }
        StudiableQuestionMetadata studiableQuestionMetadata = (StudiableQuestionMetadata) obj;
        return this.a == studiableQuestionMetadata.a && this.b == studiableQuestionMetadata.b && this.c == studiableQuestionMetadata.c && this.d == studiableQuestionMetadata.d && Intrinsics.b(this.e, studiableQuestionMetadata.e) && Intrinsics.b(this.f, studiableQuestionMetadata.f);
    }

    public final int hashCode() {
        int iE = assistantMode.refactored.a.e(this.d, assistantMode.refactored.a.e(this.c, d0.d(this.a.hashCode() * 31, 31, this.b), 31), 31);
        StudiableDiagramImage studiableDiagramImage = this.e;
        int iHashCode = (iE + (studiableDiagramImage == null ? 0 : studiableDiagramImage.hashCode())) * 31;
        StudiableQuestionSource studiableQuestionSource = this.f;
        return iHashCode + (studiableQuestionSource != null ? studiableQuestionSource.hashCode() : 0);
    }

    public final String toString() {
        return "StudiableQuestionMetadata(questionType=" + this.a + ", id=" + this.b + ", promptSide=" + this.c + ", answerSide=" + this.d + ", diagramImage=" + this.e + ", questionSource=" + this.f + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a.name());
        dest.writeLong(this.b);
        dest.writeString(this.c.name());
        dest.writeString(this.d.name());
        StudiableDiagramImage studiableDiagramImage = this.e;
        if (studiableDiagramImage == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableDiagramImage.writeToParcel(dest, i);
        }
        StudiableQuestionSource studiableQuestionSource = this.f;
        if (studiableQuestionSource == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableQuestionSource.writeToParcel(dest, i);
        }
    }
}
