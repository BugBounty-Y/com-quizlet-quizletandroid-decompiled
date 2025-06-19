package assistantMode.questions.generators;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import assistantMode.types.QuestionElement;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final ArrayList a;
    public final QuestionElement b;
    public final ArrayList c;

    public b(ArrayList options, QuestionElement answer, ArrayList optionsSource) {
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(optionsSource, "optionsSource");
        this.a = options;
        this.b = answer;
        this.c = optionsSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b.equals(bVar.b) && this.c.equals(bVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b.a);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OptionsWithAnswer(options=");
        sb.append(this.a);
        sb.append(", answer=");
        sb.append(this.b);
        sb.append(", optionsSource=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
