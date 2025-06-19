package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MixedOptionMatchingStudiableQuestion extends StudiableQuestion {

    @NotNull
    public static final Parcelable.Creator<MixedOptionMatchingStudiableQuestion> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(28);
    public final ArrayList b;
    public final StudiableQuestionMetadata c;
    public final String d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MixedOptionMatchingStudiableQuestion(ArrayList options, StudiableQuestionMetadata metadata, String kmpJson) {
        super(null);
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(kmpJson, "kmpJson");
        this.b = options;
        this.c = metadata;
        this.d = kmpJson;
    }

    @Override // com.quizlet.studiablemodels.StudiableQuestion
    public final StudiableQuestionMetadata a() {
        return this.c;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MixedOptionMatchingStudiableQuestion)) {
            return false;
        }
        MixedOptionMatchingStudiableQuestion mixedOptionMatchingStudiableQuestion = (MixedOptionMatchingStudiableQuestion) obj;
        return this.b.equals(mixedOptionMatchingStudiableQuestion.b) && Intrinsics.b(this.c, mixedOptionMatchingStudiableQuestion.c) && Intrinsics.b(this.d, mixedOptionMatchingStudiableQuestion.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MixedOptionMatchingStudiableQuestion(options=");
        sb.append(this.b);
        sb.append(", metadata=");
        sb.append(this.c);
        sb.append(", kmpJson=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        ArrayList arrayList = this.b;
        dest.writeInt(arrayList.size());
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            dest.writeParcelable((Parcelable) it2.next(), i);
        }
        this.c.writeToParcel(dest, i);
        dest.writeString(this.d);
    }
}
