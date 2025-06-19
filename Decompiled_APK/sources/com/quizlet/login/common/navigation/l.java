package com.quizlet.login.common.navigation;

import androidx.compose.ui.window.r;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.features.folders.composables.J;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class l implements com.quizlet.ui.compose.navigation.a {
    public final boolean a;

    public l(boolean z) {
        this.a = z;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return A.b(D1.b("shouldSkipUpsell", new J(this, 23)));
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
        return "parent_email";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && this.a == ((l) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("ParentEmail(shouldSkipUpsell="), this.a);
    }
}
