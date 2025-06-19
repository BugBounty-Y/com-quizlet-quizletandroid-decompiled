package com.quizlet.explanations.feedback.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class ExplanationsFeedbackSetUpState implements Parcelable {

    @Metadata
    public static final class Exercise extends ExplanationsFeedbackSetUpState {

        @NotNull
        public static final Parcelable.Creator<Exercise> CREATOR = new a();
        public final String a;
        public final String b;
        public final long c;
        public final String d;

        public Exercise(long j, String contentUrl, String exerciseId, String textbookIsbn) {
            Intrinsics.checkNotNullParameter(contentUrl, "contentUrl");
            Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
            Intrinsics.checkNotNullParameter(textbookIsbn, "textbookIsbn");
            this.a = contentUrl;
            this.b = exerciseId;
            this.c = j;
            this.d = textbookIsbn;
        }

        @Override // com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState
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
            if (!(obj instanceof Exercise)) {
                return false;
            }
            Exercise exercise = (Exercise) obj;
            return Intrinsics.b(this.a, exercise.a) && Intrinsics.b(this.b, exercise.b) && this.c == exercise.c && Intrinsics.b(this.d, exercise.d);
        }

        public final int hashCode() {
            return this.d.hashCode() + d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Exercise(contentUrl=");
            sb.append(this.a);
            sb.append(", exerciseId=");
            sb.append(this.b);
            sb.append(", textbookId=");
            sb.append(this.c);
            sb.append(", textbookIsbn=");
            return android.support.v4.media.session.a.t(sb, this.d, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            dest.writeString(this.b);
            dest.writeLong(this.c);
            dest.writeString(this.d);
        }
    }

    @Metadata
    public static final class Question extends ExplanationsFeedbackSetUpState {

        @NotNull
        public static final Parcelable.Creator<Question> CREATOR = new b();
        public final String a;
        public final String b;
        public final String c;

        public Question(String contentUrl, String id, String slug) {
            Intrinsics.checkNotNullParameter(contentUrl, "contentUrl");
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(slug, "slug");
            this.a = contentUrl;
            this.b = id;
            this.c = slug;
        }

        @Override // com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState
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
            if (!(obj instanceof Question)) {
                return false;
            }
            Question question = (Question) obj;
            return Intrinsics.b(this.a, question.a) && Intrinsics.b(this.b, question.b) && Intrinsics.b(this.c, question.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Question(contentUrl=");
            sb.append(this.a);
            sb.append(", id=");
            sb.append(this.b);
            sb.append(", slug=");
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

    public abstract String a();
}
