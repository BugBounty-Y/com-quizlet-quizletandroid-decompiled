package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class DefaultQuestionSectionData extends QuestionSectionData {

    @NotNull
    public static final Parcelable.Creator<DefaultQuestionSectionData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(25);
    public final StudiableText a;
    public final StudiableImage b;
    public final StudiableAudio c;

    public DefaultQuestionSectionData(StudiableText studiableText, StudiableImage studiableImage, StudiableAudio studiableAudio) {
        this.a = studiableText;
        this.b = studiableImage;
        this.c = studiableAudio;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DefaultQuestionSectionData)) {
            return false;
        }
        DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) obj;
        return Intrinsics.b(this.a, defaultQuestionSectionData.a) && Intrinsics.b(this.b, defaultQuestionSectionData.b) && Intrinsics.b(this.c, defaultQuestionSectionData.c);
    }

    public final int hashCode() {
        StudiableText studiableText = this.a;
        int iHashCode = (studiableText == null ? 0 : studiableText.hashCode()) * 31;
        StudiableImage studiableImage = this.b;
        int iHashCode2 = (iHashCode + (studiableImage == null ? 0 : studiableImage.hashCode())) * 31;
        StudiableAudio studiableAudio = this.c;
        return iHashCode2 + (studiableAudio != null ? studiableAudio.a.hashCode() : 0);
    }

    public final String toString() {
        return "DefaultQuestionSectionData(text=" + this.a + ", image=" + this.b + ", audio=" + this.c + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        StudiableText studiableText = this.a;
        if (studiableText == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableText.writeToParcel(dest, i);
        }
        StudiableImage studiableImage = this.b;
        if (studiableImage == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableImage.writeToParcel(dest, i);
        }
        StudiableAudio studiableAudio = this.c;
        if (studiableAudio == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableAudio.writeToParcel(dest, i);
        }
    }
}
