package com.quizlet.features.notes.detail.navigation;

import androidx.compose.ui.window.r;
import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class j implements com.quizlet.ui.compose.navigation.b, com.quizlet.ui.compose.navigation.a {
    public static final j a = new j();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.a
    public final r d() {
        return new r(3);
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "report_content";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof j);
    }

    public final int hashCode() {
        return -643679967;
    }

    public final String toString() {
        return "ReportContent";
    }
}
