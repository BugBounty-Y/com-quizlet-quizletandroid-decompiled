package com.quizlet.features.universaluploadflow.navigation;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.C1291m;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ H b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ Function0 e;

    public /* synthetic */ b(H h, Function0 function0, Function1 function1, Function0 function02, int i) {
        this.a = i;
        this.b = h;
        this.c = function0;
        this.d = function1;
        this.e = function02;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                C1291m it2 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it2, "it");
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(-349152939);
                H h = this.b;
                boolean zH = c0814p.h(h);
                Object objI = c0814p.I();
                if (zH || objI == C0804k.a) {
                    com.quizlet.features.flashcards.navigation.c cVar = new com.quizlet.features.flashcards.navigation.c(0, h, H.class, "navigateUp", "navigateUp()Z", 8, 19);
                    c0814p.i0(cVar);
                    objI = cVar;
                }
                c0814p.p(false);
                AbstractC3448e4.d((Function0) objI, this.c, this.d, this.e, null, c0814p, 3504);
                break;
            default:
                C1291m it3 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it3, "it");
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(-349141099);
                H h2 = this.b;
                boolean zH2 = c0814p2.h(h2);
                Object objI2 = c0814p2.I();
                if (zH2 || objI2 == C0804k.a) {
                    objI2 = new com.quizlet.features.flashcards.navigation.c(0, h2, H.class, "navigateUp", "navigateUp()Z", 8, 20);
                    c0814p2.i0(objI2);
                }
                c0814p2.p(false);
                Y3.i((Function0) objI2, this.c, this.d, this.e, null, null, c0814p2, 3504);
                break;
        }
        return Unit.a;
    }
}
