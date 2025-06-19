package com.quizlet.login.common.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class i implements com.quizlet.ui.compose.navigation.b {
    public static final i a = new i();

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
        return "invalid_magic_link";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof i);
    }

    public final int hashCode() {
        return 918367649;
    }

    public final String toString() {
        return "InvalidMagicLink";
    }
}
