package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class FillInTheBlankStudiableSegment implements Parcelable {

    @Metadata
    public static final class Blank extends FillInTheBlankStudiableSegment {
        public static final Blank a = new Blank();

        @NotNull
        public static final Parcelable.Creator<Blank> CREATOR = new b();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Text extends FillInTheBlankStudiableSegment {

        @NotNull
        public static final Parcelable.Creator<Text> CREATOR = new c();
        public final String a;

        public Text(String text) {
            Intrinsics.checkNotNullParameter(text, "text");
            this.a = text;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Text) && Intrinsics.b(this.a, ((Text) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("Text(text="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }
}
