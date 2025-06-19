package com.quizlet.features.settings.composables.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class m implements com.quizlet.ui.compose.navigation.b {
    public static final m a = new m();

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
        return "changeTheme";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof m);
    }

    public final int hashCode() {
        return -862501600;
    }

    public final String toString() {
        return "Screen";
    }
}
