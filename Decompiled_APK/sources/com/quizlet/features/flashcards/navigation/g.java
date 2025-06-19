package com.quizlet.features.flashcards.navigation;

import androidx.compose.ui.window.r;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import java.util.List;
import kotlin.collections.K;

/* loaded from: classes2.dex */
public final class g implements com.quizlet.ui.compose.navigation.b, com.quizlet.ui.compose.navigation.a {
    public static final g a = new g();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.a
    public final r d() {
        return O5.d();
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "flashcards_settings";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof g);
    }

    public final int hashCode() {
        return -1612840707;
    }

    public final String toString() {
        return "FlashcardsSettings";
    }
}
