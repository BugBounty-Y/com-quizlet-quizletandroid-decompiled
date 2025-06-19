package com.quizlet.explanations.textbook.exercisedetail.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class ExerciseDetailSetupState implements Parcelable {

    @Metadata
    public static final class DeepLink extends ExerciseDetailSetupState {

        @NotNull
        public static final Parcelable.Creator<DeepLink> CREATOR = new b();
        public final String a;

        public DeepLink(String id) {
            Intrinsics.checkNotNullParameter(id, "id");
            this.a = id;
        }

        @Override // com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState
        public final String a() {
            return this.a;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof DeepLink) && Intrinsics.b(this.a, ((DeepLink) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("DeepLink(id="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }

    @Metadata
    public static final class Textbook extends ExerciseDetailSetupState {

        @NotNull
        public static final Parcelable.Creator<Textbook> CREATOR = new c();
        public final String a;

        public Textbook(String id) {
            Intrinsics.checkNotNullParameter(id, "id");
            this.a = id;
        }

        @Override // com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState
        public final String a() {
            return this.a;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Textbook) && Intrinsics.b(this.a, ((Textbook) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("Textbook(id="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }

    public abstract String a();
}
