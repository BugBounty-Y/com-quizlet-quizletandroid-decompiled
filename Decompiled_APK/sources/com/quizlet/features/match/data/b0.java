package com.quizlet.features.match.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b0 extends AbstractC4353i {
    public final ArrayList a;

    public b0(ArrayList matchCards) {
        Intrinsics.checkNotNullParameter(matchCards, "matchCards");
        this.a = matchCards;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b0) && this.a.equals(((b0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("StandardBoardData(matchCards="), this.a);
    }
}
