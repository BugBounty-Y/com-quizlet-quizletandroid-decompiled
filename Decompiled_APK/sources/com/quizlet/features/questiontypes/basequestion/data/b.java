package com.quizlet.features.questiontypes.basequestion.data;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.DBAnswer;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final DBAnswer a;
    public final List b;

    public b(DBAnswer answer, List questionAttributes) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(questionAttributes, "questionAttributes");
        this.a = answer;
        this.b = questionAttributes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return d0.f(this.a.hashCode() * 31, 923521, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionFinishedState(answer=");
        sb.append(this.a);
        sb.append(", questionAttributes=");
        return android.support.v4.media.session.a.n(", answerText=null, answerImage=null, answerAudio=null, answerShape=null)", sb, this.b);
    }
}
