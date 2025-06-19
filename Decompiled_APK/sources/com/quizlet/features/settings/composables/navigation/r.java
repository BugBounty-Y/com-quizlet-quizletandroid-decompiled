package com.quizlet.features.settings.composables.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class r implements com.quizlet.ui.compose.navigation.b {
    public static final r a = new r();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return A.b(D1.b("reauthType", new com.quizlet.features.practicetest.navigation.a(27)));
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "deleteAccount/{reauthType}";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof r);
    }

    public final int hashCode() {
        return -1780472413;
    }

    public final String toString() {
        return "DeleteAccount";
    }
}
