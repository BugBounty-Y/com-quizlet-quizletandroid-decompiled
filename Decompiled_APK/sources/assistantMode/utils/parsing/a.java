package assistantMode.utils.parsing;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final ArrayList b;
    public final m c;
    public final m d;

    public a(String prompt, ArrayList options, m mVar, m mVar2) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(options, "options");
        this.a = prompt;
        this.b = options;
        this.c = mVar;
        this.d = mVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a.equals(aVar.a) && this.b.equals(aVar.b) && this.c == aVar.c && this.d == aVar.d;
    }

    public final int hashCode() {
        int iH = d0.h(this.b, this.a.hashCode() * 31, 31);
        m mVar = this.c;
        int iHashCode = (iH + (mVar == null ? 0 : mVar.hashCode())) * 31;
        m mVar2 = this.d;
        return Boolean.hashCode(false) + ((iHashCode + (mVar2 == null ? 0 : mVar2.hashCode())) * 31);
    }

    public final String toString() {
        return "MultipleChoiceQuestion(prompt=" + this.a + ", options=" + this.b + ", promptSide=" + this.c + ", answerSide=" + this.d + ", renderTags=false)";
    }
}
