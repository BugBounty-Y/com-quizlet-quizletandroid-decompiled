package com.quizlet.login.common.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class j implements com.quizlet.ui.compose.navigation.b {
    public static final j a = new j();

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
        return "login";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof j);
    }

    public final int hashCode() {
        return -563194504;
    }

    public final String toString() {
        return "Login";
    }
}
