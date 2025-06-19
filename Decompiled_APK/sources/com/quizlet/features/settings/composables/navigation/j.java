package com.quizlet.features.settings.composables.navigation;

import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class j implements com.quizlet.ui.compose.navigation.b, com.quizlet.ui.compose.navigation.a {
    public static final j a = new j();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return K.a;
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
        return "changePasswordDialog";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof j);
    }

    public final int hashCode() {
        return -1309897492;
    }

    public final String toString() {
        return "Dialog";
    }
}
