package com.quizlet.login.common.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.features.folders.composables.J;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class n implements com.quizlet.ui.compose.navigation.b {
    public final boolean a;

    public n(boolean z) {
        this.a = z;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return A.b(D1.b("shouldSkipUpsell", new J(this, 24)));
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "signup";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && this.a == ((n) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("SignUp(shouldSkipUpsell="), this.a);
    }
}
