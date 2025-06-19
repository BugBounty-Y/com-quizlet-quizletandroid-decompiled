package com.quizlet.features.universaluploadflow.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.data.model.m2;
import com.quizlet.features.folders.composables.J;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements com.quizlet.ui.compose.navigation.b {
    public final m2 a;
    public final List b;
    public final String c;

    public h(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        this.b = A.b(D1.b("source", new J(this, 19)));
        this.c = "upload_flow";
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return this.b;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && this.a == ((h) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UploadFlow(source=" + this.a + ")";
    }
}
