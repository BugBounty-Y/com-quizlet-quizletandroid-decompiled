package com.quizlet.explanations.textbook.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class TextbookSetUpState implements Parcelable {

    @Metadata
    public static final class Exercise extends TextbookSetUpState {

        @NotNull
        public static final Parcelable.Creator<Exercise> CREATOR = new r();
        public final String a;

        public Exercise(String id) {
            Intrinsics.checkNotNullParameter(id, "id");
            this.a = id;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Exercise) && Intrinsics.b(this.a, ((Exercise) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("Exercise(id="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }

    @Metadata
    public static final class TableOfContents extends TextbookSetUpState {

        @NotNull
        public static final Parcelable.Creator<TableOfContents> CREATOR = new s();
        public final String a;

        public TableOfContents(String isbn) {
            Intrinsics.checkNotNullParameter(isbn, "isbn");
            this.a = isbn;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof TableOfContents) && Intrinsics.b(this.a, ((TableOfContents) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("TableOfContents(isbn="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }
}
