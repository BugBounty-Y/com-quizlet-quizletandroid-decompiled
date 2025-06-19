package com.quizlet.search.data.term;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.K0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class TermSearchUiModel implements Parcelable, com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {

    @NotNull
    public static final Parcelable.Creator<TermSearchUiModel> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(22);
    public final long a;
    public final long b;
    public final long c;
    public final String d;
    public final int e;
    public final TermUiModel f;
    public final K0 g;

    public TermSearchUiModel(long j, long j2, long j3, String setName, int i, TermUiModel highlightedTerm) {
        Intrinsics.checkNotNullParameter(setName, "setName");
        Intrinsics.checkNotNullParameter(highlightedTerm, "highlightedTerm");
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = setName;
        this.e = i;
        this.f = highlightedTerm;
        this.g = K0.FREE;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.g;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TermSearchUiModel)) {
            return false;
        }
        TermSearchUiModel termSearchUiModel = (TermSearchUiModel) obj;
        return this.a == termSearchUiModel.a && this.b == termSearchUiModel.b && this.c == termSearchUiModel.c && Intrinsics.b(this.d, termSearchUiModel.d) && this.e == termSearchUiModel.e && Intrinsics.b(this.f, termSearchUiModel.f);
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final long getItemId() {
        return this.a;
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        return Long.valueOf(this.a);
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final int getModelType() {
        return 11;
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.b(this.e, d0.e(d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31);
    }

    public final String toString() {
        return "TermSearchUiModel(termId=" + this.a + ", setId=" + this.b + ", creatorId=" + this.c + ", setName=" + this.d + ", termCount=" + this.e + ", highlightedTerm=" + this.f + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a);
        dest.writeLong(this.b);
        dest.writeLong(this.c);
        dest.writeString(this.d);
        dest.writeInt(this.e);
        this.f.writeToParcel(dest, i);
    }
}
