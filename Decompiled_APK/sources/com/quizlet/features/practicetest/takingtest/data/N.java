package com.quizlet.features.practicetest.takingtest.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class N {
    public final int a;
    public final ArrayList b;

    public N(int i, ArrayList questionFormats) {
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        this.a = i;
        this.b = questionFormats;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof N)) {
            return false;
        }
        N n = (N) obj;
        return this.a == n.a && this.b.equals(n.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TestConfiguration(questionCount=");
        sb.append(this.a);
        sb.append(", questionFormats=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
