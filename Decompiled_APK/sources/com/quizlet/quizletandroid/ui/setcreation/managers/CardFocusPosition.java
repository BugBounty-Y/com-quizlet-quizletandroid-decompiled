package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.O1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CardFocusPosition implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<CardFocusPosition> CREATOR = new c();
    public final int a;
    public final int b;
    public final O1 c;

    public CardFocusPosition(int i, int i2, O1 o1) {
        this.a = i;
        this.b = i2;
        this.c = o1;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CardFocusPosition)) {
            return false;
        }
        CardFocusPosition cardFocusPosition = (CardFocusPosition) obj;
        return this.a == cardFocusPosition.a && this.b == cardFocusPosition.b && this.c == cardFocusPosition.c;
    }

    public final int hashCode() {
        int iB = d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        O1 o1 = this.c;
        return iB + (o1 == null ? 0 : o1.hashCode());
    }

    public final String toString() {
        return "CardFocusPosition(termPosition=" + this.a + ", adapterPosition=" + this.b + ", termSide=" + this.c + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
        dest.writeInt(this.b);
        O1 o1 = this.c;
        if (o1 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(o1.name());
        }
    }
}
