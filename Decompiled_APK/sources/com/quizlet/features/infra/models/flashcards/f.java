package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final e a;
    public final D6 b;
    public final G c;
    public final io.reactivex.rxjava3.subjects.d d;

    public f(D6 faceViewState, G onAudioClick) {
        e onboardingState = new e();
        io.reactivex.rxjava3.subjects.d playIndicatorObservable = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullParameter(onboardingState, "onboardingState");
        Intrinsics.checkNotNullParameter(faceViewState, "faceViewState");
        Intrinsics.checkNotNullParameter(onAudioClick, "onAudioClick");
        Intrinsics.checkNotNullParameter(playIndicatorObservable, "playIndicatorObservable");
        this.a = onboardingState;
        this.b = faceViewState;
        this.c = onAudioClick;
        this.d = playIndicatorObservable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && Intrinsics.b(this.d, fVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "FlipCardFaceViewUIData(onboardingState=" + this.a + ", faceViewState=" + this.b + ", onAudioClick=" + this.c + ", playIndicatorObservable=" + this.d + ")";
    }
}
