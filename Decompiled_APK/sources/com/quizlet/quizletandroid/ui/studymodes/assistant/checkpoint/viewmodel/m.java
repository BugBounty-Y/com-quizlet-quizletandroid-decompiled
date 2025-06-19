package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m {
    public final String a;

    public m(String imageUrl) {
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = imageUrl;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Image(imageUrl="), this.a, ")");
    }
}
