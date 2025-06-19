package com.quizlet.explanations.textbook.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6;
import com.quizlet.generated.enums.y1;
import com.quizlet.ui.compose.C4832z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import org.slf4j.helpers.k;

/* loaded from: classes2.dex */
public final /* synthetic */ class g implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ Function1 f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ g(n nVar, boolean z, Function0 function0, boolean z2, boolean z3, String str, y1 y1Var, com.quizlet.features.infra.folder.menu.viewmodel.n nVar2, Function1 function1, Function1 function12, int i) {
        this.g = nVar;
        this.b = z;
        this.h = function0;
        this.c = z2;
        this.d = z3;
        this.i = str;
        this.j = y1Var;
        this.k = nVar2;
        this.e = function1;
        this.f = function12;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                String str = (String) this.i;
                Function1 function1 = this.e;
                Function1 function12 = this.f;
                k.b((n) this.g, this.b, (Function0) this.h, this.c, this.d, str, (y1) this.j, (com.quizlet.features.infra.folder.menu.viewmodel.n) this.k, function1, function12, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function1 function13 = this.f;
                Function1 function14 = (Function1) this.k;
                AbstractC3152g6.a((com.quizlet.features.infra.folder.menu.data.b) this.g, (q) this.h, this.b, this.c, this.d, (kotlinx.collections.immutable.c) this.i, (C4832z) this.j, this.e, function13, function14, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ g(com.quizlet.features.infra.folder.menu.data.b bVar, q qVar, boolean z, boolean z2, boolean z3, kotlinx.collections.immutable.c cVar, C4832z c4832z, Function1 function1, Function1 function12, Function1 function13, int i) {
        this.g = bVar;
        this.h = qVar;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.i = cVar;
        this.j = c4832z;
        this.e = function1;
        this.f = function12;
        this.k = function13;
    }
}
