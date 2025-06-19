package com.quizlet.features.settings.composables.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class s implements com.quizlet.ui.compose.navigation.b {
    public static final s a = new s();

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
        return "settings";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof s);
    }

    public final int hashCode() {
        return -545747998;
    }

    public final String toString() {
        return "Settings";
    }
}
