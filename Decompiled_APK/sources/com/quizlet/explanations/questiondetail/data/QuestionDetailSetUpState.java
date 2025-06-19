package com.quizlet.explanations.questiondetail.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class QuestionDetailSetUpState implements Parcelable {

    @Metadata
    public static final class WithId extends QuestionDetailSetUpState {

        @NotNull
        public static final Parcelable.Creator<WithId> CREATOR = new j();
        public final String a;

        public WithId(String id) {
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
            return (obj instanceof WithId) && Intrinsics.b(this.a, ((WithId) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("WithId(id="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }
}
