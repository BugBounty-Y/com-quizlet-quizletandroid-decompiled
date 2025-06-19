package com.quizlet.login.common.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class f implements com.quizlet.ui.compose.navigation.b {
    public static final f a = new f();

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
        return "email_sent";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof f);
    }

    public final int hashCode() {
        return -1864685597;
    }

    public final String toString() {
        return "EmailSent";
    }
}
