package test.utils;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final double a;
    public final ArrayList b;

    public g(double d, ArrayList gradedAnswers) {
        Intrinsics.checkNotNullParameter(gradedAnswers, "gradedAnswers");
        this.a = d;
        this.b = gradedAnswers;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Double.compare(this.a, gVar.a) == 0 && this.b.equals(gVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Double.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Result(gradePercentage=");
        sb.append(this.a);
        sb.append(", gradedAnswers=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
