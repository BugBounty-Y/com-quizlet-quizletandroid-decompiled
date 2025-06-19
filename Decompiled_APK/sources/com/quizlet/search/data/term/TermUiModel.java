package com.quizlet.search.data.term;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class TermUiModel implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<TermUiModel> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(23);
    public final String a;
    public final String b;
    public final String c;

    public TermUiModel(String term, String definition, String str) {
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(definition, "definition");
        this.a = term;
        this.b = definition;
        this.c = str;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TermUiModel)) {
            return false;
        }
        TermUiModel termUiModel = (TermUiModel) obj;
        return Intrinsics.b(this.a, termUiModel.a) && Intrinsics.b(this.b, termUiModel.b) && Intrinsics.b(this.c, termUiModel.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TermUiModel(term=");
        sb.append(this.a);
        sb.append(", definition=");
        sb.append(this.b);
        sb.append(", imageUrl=");
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
