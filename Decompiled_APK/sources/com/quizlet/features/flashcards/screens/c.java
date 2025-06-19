package com.quizlet.features.flashcards.screens;

import androidx.lifecycle.A;
import androidx.lifecycle.H;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import com.quizlet.features.questiontypes.basequestion.i;
import com.quizlet.features.questiontypes.basequestion.k;
import com.quizlet.features.questiontypes.selfassessment.h;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements H {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ c(i iVar, J j, h hVar) {
        this.a = 1;
        this.c = iVar;
        this.b = j;
        this.d = hVar;
    }

    @Override // androidx.lifecycle.H
    public final void d(J j, A event) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                if (f.a[event.ordinal()] == 1) {
                    E.A(p0.h((J) this.b), null, null, new e((com.quizlet.features.infra.ui.feedback.sound.soundeffect.b) this.c, (com.quizlet.features.infra.ui.feedback.sound.soundeffect.e) this.d, null), 3);
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                if (com.quizlet.features.questiontypes.selfassessment.ui.e.a[event.ordinal()] == 1) {
                    ((k) ((i) this.c)).h.f((J) this.b, new com.quizlet.ads.ui.fragments.c(new G(1, (h) this.d, h.class, "onAudioSettingsChanged", "onAudioSettingsChanged(Z)V", 0, 23), (byte) 0));
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                if (event == A.ON_CREATE) {
                    com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G g = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G) this.b;
                    g.getClass();
                    Intrinsics.checkNotNullParameter("results", "screen");
                    com.quizlet.features.infra.basestudy.manager.f.k(g.D, "results", null, 6);
                    t tVar = (t) this.d;
                    com.quizlet.quizletandroid.ui.studymodes.testmode.compose.d dVar = new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.d(tVar, g, null);
                    androidx.lifecycle.E e = (androidx.lifecycle.E) this.c;
                    E.A(e, null, null, dVar, 3);
                    E.A(e, null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.f(tVar, g, null), 3);
                    E.A(e, null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.h(tVar, g, null), 3);
                    break;
                }
                break;
        }
    }

    public /* synthetic */ c(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }
}
