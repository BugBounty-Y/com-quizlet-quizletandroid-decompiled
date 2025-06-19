package com.quizlet.features.flashcards;

import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class x implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ S b;

    public /* synthetic */ x(S s, int i) {
        this.a = i;
        this.b = s;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                S s = this.b;
                s.x = zBooleanValue;
                s.H();
                break;
            default:
                com.quizlet.features.flashcards.data.e eVar = (com.quizlet.features.flashcards.data.e) obj;
                if (eVar != null) {
                    S s2 = this.b;
                    s2.d.b(true);
                    kotlinx.coroutines.E.A(p0.j(s2), null, null, new Q(eVar, s2, null), 3);
                }
                break;
        }
        return Unit.a;
    }
}
