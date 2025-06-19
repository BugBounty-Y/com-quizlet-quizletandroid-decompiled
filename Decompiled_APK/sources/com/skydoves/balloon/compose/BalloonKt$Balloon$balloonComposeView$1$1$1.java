package com.skydoves.balloon.compose;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.W0;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.compose.ui.semantics.m;
import androidx.compose.ui.semantics.v;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt$Balloon$balloonComposeView$1$1$1 implements kotlin.jvm.functions.c {
    final /* synthetic */ W0 $currentContent$delegate;

    public BalloonKt$Balloon$balloonComposeView$1$1$1(W0 w0) {
        this.$currentContent$delegate = w0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit invoke$lambda$1$lambda$0(v semantics) {
        Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
        BalloonSemanticsKt.balloon(semantics);
        return Unit.a;
    }

    @Override // kotlin.jvm.functions.c
    public /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2, Object obj3) {
        invoke((BalloonComposeView) obj, (InterfaceC0806l) obj2, ((Number) obj3).intValue());
        return Unit.a;
    }

    public final void invoke(BalloonComposeView it2, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if ((i & 17) == 16) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            if (c0814p.x()) {
                c0814p.Q();
                return;
            }
        }
        n nVar = n.b;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.X(-829360011);
        Object objI = c0814p2.I();
        if (objI == C0804k.a) {
            objI = new f(0);
            c0814p2.i0(objI);
        }
        c0814p2.p(false);
        q qVarA = m.a(nVar, false, (Function1) objI);
        final W0 w0 = this.$currentContent$delegate;
        BalloonKt.BalloonLayout(qVarA, androidx.compose.runtime.internal.e.e(1986328809, new Function2<InterfaceC0806l, Integer, Unit>() { // from class: com.skydoves.balloon.compose.BalloonKt$Balloon$balloonComposeView$1$1$1.2
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2) {
                invoke((InterfaceC0806l) obj, ((Number) obj2).intValue());
                return Unit.a;
            }

            public final void invoke(InterfaceC0806l interfaceC0806l2, int i2) {
                if ((i2 & 3) == 2) {
                    C0814p c0814p3 = (C0814p) interfaceC0806l2;
                    if (c0814p3.x()) {
                        c0814p3.Q();
                        return;
                    }
                }
                Function2 function2Balloon$lambda$8 = BalloonKt.Balloon$lambda$8(w0);
                if (function2Balloon$lambda$8 == null) {
                    return;
                }
                function2Balloon$lambda$8.invoke(interfaceC0806l2, 0);
            }
        }, c0814p2), c0814p2, 48, 0);
    }
}
