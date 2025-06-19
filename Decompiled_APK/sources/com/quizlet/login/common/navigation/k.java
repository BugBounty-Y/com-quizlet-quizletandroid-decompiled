package com.quizlet.login.common.navigation;

import androidx.compose.ui.window.r;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class k implements com.quizlet.ui.compose.navigation.a {
    public static final k a = new k();

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
        return "multiple_accounts_found";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof k);
    }

    public final int hashCode() {
        return -1153845477;
    }

    public final String toString() {
        return "MultipleAccountsFound";
    }
}
