package com.google.firebase.perf.injection.modules;

import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.h;
import com.google.firebase.installations.d;
import com.quizlet.quizletandroid.u;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class b implements c {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                h hVar = (h) ((com.quizlet.data.repository.explanations.exercise.b) this.b).a;
                S6.c(hVar);
                return hVar;
            case 1:
                d dVar = (d) ((com.quizlet.data.repository.explanations.exercise.b) this.b).b;
                S6.c(dVar);
                return dVar;
            case 2:
                com.google.firebase.inject.b bVar = (com.google.firebase.inject.b) ((com.quizlet.data.repository.explanations.exercise.b) this.b).c;
                S6.c(bVar);
                return bVar;
            case 3:
                com.google.firebase.inject.b bVar2 = (com.google.firebase.inject.b) ((com.quizlet.data.repository.explanations.exercise.b) this.b).d;
                S6.c(bVar2);
                return bVar2;
            default:
                return new com.quizlet.quizletandroid.ui.profile.data.c(((u) this.b).U());
        }
    }
}
