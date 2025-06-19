package androidx.compose.animation.core;

import android.content.Context;
import android.view.View;
import androidx.activity.C0036h;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;
import androidx.navigation.C1291m;
import androidx.navigation.compose.C1276i;
import androidx.navigation.compose.C1281n;
import java.util.Iterator;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class P implements androidx.compose.runtime.G {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ P(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // androidx.compose.runtime.G
    public final void dispose() {
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                ((N) obj2).a.n((J) obj);
                break;
            case 1:
                ((E0) obj2).j.remove((E0) obj);
                break;
            case 2:
                E0 e0 = (E0) obj2;
                e0.getClass();
                C0272v0 c0272v0 = (C0272v0) ((androidx.compose.runtime.L0) ((w0) obj).b).getValue();
                if (c0272v0 != null) {
                    e0.i.remove(c0272v0.a);
                    break;
                }
                break;
            case 3:
                ((E0) obj2).i.remove((z0) obj);
                break;
            case 4:
                androidx.compose.foundation.layout.S0 s0 = (androidx.compose.foundation.layout.S0) obj2;
                int i = s0.u - 1;
                s0.u = i;
                if (i == 0) {
                    WeakHashMap weakHashMap = androidx.core.view.V.a;
                    View view = (View) obj;
                    androidx.core.view.L.m(view, null);
                    androidx.core.view.V.r(view, null);
                    view.removeOnAttachStateChangeListener(s0.v);
                    break;
                }
                break;
            case 5:
                ((androidx.compose.foundation.lazy.layout.l0) obj2).c.add(obj);
                break;
            case 6:
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) obj2;
                androidx.compose.foundation.interaction.o oVar = (androidx.compose.foundation.interaction.o) interfaceC0773a0.getValue();
                if (oVar != null) {
                    androidx.compose.foundation.interaction.n nVar = new androidx.compose.foundation.interaction.n(oVar);
                    androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) obj;
                    if (lVar != null) {
                        lVar.a(nVar);
                    }
                    interfaceC0773a0.setValue(null);
                    break;
                }
                break;
            case 7:
                ((androidx.compose.foundation.text.N0) obj2).d.remove((Function1) obj);
                break;
            case 8:
                ((androidx.lifecycle.T) obj2).k((androidx.camera.camera2.internal.D) obj);
                break;
            case 9:
                ((Context) obj2).getApplicationContext().unregisterComponentCallbacks((androidx.compose.ui.platform.P) obj);
                break;
            case 10:
                ((Context) obj2).getApplicationContext().unregisterComponentCallbacks((androidx.compose.ui.platform.Q) obj);
                break;
            case 11:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((C0036h) obj);
                break;
            case 12:
                ((C1291m) obj2).h.j.b((C1281n) obj);
                break;
            case 13:
                Iterator it2 = ((List) ((W0) obj2).getValue()).iterator();
                while (it2.hasNext()) {
                    ((C1276i) obj).b().c((C1291m) it2.next());
                }
                break;
            case 14:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((androidx.activity.result.c) obj);
                break;
            case 15:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((com.quizlet.diagrams.ui.g) obj);
                break;
            case 16:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((com.quizlet.features.flashcards.screens.c) obj);
                break;
            case 17:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((C0036h) obj);
                break;
            case 18:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((com.quizlet.features.flashcards.screens.c) obj);
                break;
            case 19:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((androidx.emoji2.text.k) obj);
                break;
            case 20:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.d) obj);
                break;
            case 21:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.d) obj);
                break;
            default:
                ((androidx.lifecycle.J) obj2).getLifecycle().b((com.quizlet.features.flashcards.screens.c) obj);
                break;
        }
    }
}
