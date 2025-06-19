package com.quizlet.features.questiontypes.mcq;

import com.google.android.gms.internal.mlkit_vision_camera.X2;

/* loaded from: classes3.dex */
public final class q extends X2 {
    public final int a;

    public q(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && this.a == ((q) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("ChoiceSelected(position="), this.a, ")");
    }
}
