package com.quizlet.features.practicetest.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class g implements com.quizlet.ui.compose.navigation.b {
    public static final g a = new g();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "results";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof g);
    }

    public final int hashCode() {
        return 1497504635;
    }

    public final String toString() {
        return "Results";
    }
}
