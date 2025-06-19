package com.quizlet.features.practicetest.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.features.folders.composables.J;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements com.quizlet.ui.compose.navigation.b {
    public final String a;

    public e(String str) {
        this.a = str;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return A.b(D1.b("questionBankUuid", new J(this, 8)));
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "practiceTest";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTest(questionBankUuid="), this.a, ")");
    }
}
