package com.quizlet.features.settings.composables.navigation;

import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements i, com.quizlet.ui.compose.navigation.a {
    public static final t a = new t();

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
        return "updateEmailDialog/{authToken}";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof t);
    }

    public final int hashCode() {
        return -1045409694;
    }

    public final String toString() {
        return "Dialog";
    }
}
