package assistantMode.types;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class w {
    public final List a;
    public final ArrayList b;

    public w(ArrayList desiredQuestionTypes, List questionSpecs) {
        Intrinsics.checkNotNullParameter(questionSpecs, "questionSpecs");
        Intrinsics.checkNotNullParameter(desiredQuestionTypes, "desiredQuestionTypes");
        this.a = questionSpecs;
        this.b = desiredQuestionTypes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return this.a.equals(wVar.a) && this.b.equals(wVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RoundOutline(questionSpecs=");
        sb.append(this.a);
        sb.append(", desiredQuestionTypes=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
