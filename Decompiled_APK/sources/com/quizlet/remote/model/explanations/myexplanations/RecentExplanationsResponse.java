package com.quizlet.remote.model.explanations.myexplanations;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RecentExplanationsResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;
        public final List b;
        public final List c;

        public Models(@InterfaceC4853h(name = "question") @NotNull List<RemoteQuestion> questions, @InterfaceC4853h(name = "textbook") @NotNull List<RemoteTextbook> textbooks, @InterfaceC4853h(name = "textbookExercise") @NotNull List<RemoteExerciseDetails> textbookExercises) {
            Intrinsics.checkNotNullParameter(questions, "questions");
            Intrinsics.checkNotNullParameter(textbooks, "textbooks");
            Intrinsics.checkNotNullParameter(textbookExercises, "textbookExercises");
            this.a = questions;
            this.b = textbooks;
            this.c = textbookExercises;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "question") @NotNull List<RemoteQuestion> questions, @InterfaceC4853h(name = "textbook") @NotNull List<RemoteTextbook> textbooks, @InterfaceC4853h(name = "textbookExercise") @NotNull List<RemoteExerciseDetails> textbookExercises) {
            Intrinsics.checkNotNullParameter(questions, "questions");
            Intrinsics.checkNotNullParameter(textbooks, "textbooks");
            Intrinsics.checkNotNullParameter(textbookExercises, "textbookExercises");
            return new Models(questions, textbooks, textbookExercises);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Models)) {
                return false;
            }
            Models models = (Models) obj;
            return Intrinsics.b(this.a, models.a) && Intrinsics.b(this.b, models.b) && Intrinsics.b(this.c, models.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Models(questions=");
            sb.append(this.a);
            sb.append(", textbooks=");
            sb.append(this.b);
            sb.append(", textbookExercises=");
            return android.support.v4.media.session.a.n(")", sb, this.c);
        }
    }

    public RecentExplanationsResponse(@InterfaceC4853h(name = "models") @NotNull Models models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RecentExplanationsResponse copy(@InterfaceC4853h(name = "models") @NotNull Models models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RecentExplanationsResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RecentExplanationsResponse) && Intrinsics.b(this.d, ((RecentExplanationsResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "RecentExplanationsResponse(models=" + this.d + ")";
    }
}
