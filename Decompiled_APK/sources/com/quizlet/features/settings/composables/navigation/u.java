package com.quizlet.features.settings.composables.navigation;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements i {
    public static final u a = new u();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return AbstractC3489l3.a();
    }

    @Override // com.quizlet.features.settings.composables.navigation.i
    public final String b(String reAuthToken) {
        Intrinsics.checkNotNullParameter(reAuthToken, "reAuthToken");
        return AbstractC3489l3.b(this, reAuthToken);
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "updateEmail/{authToken}";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof u);
    }

    public final int hashCode() {
        return -621014138;
    }

    public final String toString() {
        return "Screen";
    }
}
