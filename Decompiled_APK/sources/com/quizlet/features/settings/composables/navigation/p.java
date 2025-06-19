package com.quizlet.features.settings.composables.navigation;

import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements i, com.quizlet.ui.compose.navigation.a {
    public static final p a = new p();

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

    @Override // com.quizlet.ui.compose.navigation.a
    public final androidx.compose.ui.window.r d() {
        return O5.d();
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "createPasswordDialog/{authToken}";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof p);
    }

    public final int hashCode() {
        return 304102944;
    }

    public final String toString() {
        return "Dialog";
    }
}
