package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3619f6;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u extends AbstractC3619f6 {
    public final Map a;

    public u(Map data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u) && Intrinsics.b(this.a, ((u) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SchoolCourseRecsState(data=" + this.a + ")";
    }
}
