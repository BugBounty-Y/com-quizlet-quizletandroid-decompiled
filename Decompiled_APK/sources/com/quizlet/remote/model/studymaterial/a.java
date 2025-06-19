package com.quizlet.remote.model.studymaterial;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final List a;
    public final List b;
    public final List c;
    public final List d;
    public final List e;
    public final List f;
    public final List g;
    public final List h;

    public a(List studyMaterials, List explanationQuestions, List flashcardSets, List folders, List textbooks, List textbookExercises, List studyNotes, List users) {
        Intrinsics.checkNotNullParameter(studyMaterials, "studyMaterials");
        Intrinsics.checkNotNullParameter(explanationQuestions, "explanationQuestions");
        Intrinsics.checkNotNullParameter(flashcardSets, "flashcardSets");
        Intrinsics.checkNotNullParameter(folders, "folders");
        Intrinsics.checkNotNullParameter(textbooks, "textbooks");
        Intrinsics.checkNotNullParameter(textbookExercises, "textbookExercises");
        Intrinsics.checkNotNullParameter(studyNotes, "studyNotes");
        Intrinsics.checkNotNullParameter(users, "users");
        this.a = studyMaterials;
        this.b = explanationQuestions;
        this.c = flashcardSets;
        this.d = folders;
        this.e = textbooks;
        this.f = textbookExercises;
        this.g = studyNotes;
        this.h = users;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f) && Intrinsics.b(this.g, aVar.g) && Intrinsics.b(this.h, aVar.h);
    }

    public final int hashCode() {
        return this.h.hashCode() + d0.f(d0.f(d0.f(d0.f(d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Model(studyMaterials=");
        sb.append(this.a);
        sb.append(", explanationQuestions=");
        sb.append(this.b);
        sb.append(", flashcardSets=");
        sb.append(this.c);
        sb.append(", folders=");
        sb.append(this.d);
        sb.append(", textbooks=");
        sb.append(this.e);
        sb.append(", textbookExercises=");
        sb.append(this.f);
        sb.append(", studyNotes=");
        sb.append(this.g);
        sb.append(", users=");
        return android.support.v4.media.session.a.n(")", sb, this.h);
    }
}
