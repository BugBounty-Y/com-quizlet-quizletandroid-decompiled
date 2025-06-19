package com.quizlet.features.infra.folder.composable;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3627g6;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.d;
import com.quizlet.themes.e;
import com.skydoves.balloon.compose.BalloonWindow;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements kotlin.jvm.functions.c {
    public final /* synthetic */ com.quizlet.features.infra.folder.a a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ int c;

    public c(com.quizlet.features.infra.folder.a aVar, Function1 function1, int i) {
        this.a = aVar;
        this.b = function1;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        BalloonWindow it2 = (BalloonWindow) obj;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
        ((Number) obj3).intValue();
        Intrinsics.checkNotNullParameter(it2, "it");
        C0814p c0814p = (C0814p) interfaceC0806l;
        ((d) c0814p.j(e.a)).a.getClass();
        androidx.compose.ui.graphics.painter.b bVarF = com.quizlet.ui.resources.icons.d.F(interfaceC0806l);
        String strD = AbstractC3106b5.d(interfaceC0806l, R.string.new_tag_add);
        com.quizlet.features.infra.folder.a aVar = this.a;
        c0814p.X(-1683761765);
        Function1 function1 = this.b;
        boolean zF = c0814p.f(function1);
        int i = this.c;
        boolean zD = zF | c0814p.d(i);
        Object objI = c0814p.I();
        if (zD || objI == C0804k.a) {
            objI = new b(function1, i, 1);
            c0814p.i0(objI);
        }
        c0814p.p(false);
        AbstractC3627g6.a(bVarF, strD, null, aVar.c, (Function0) objI, c0814p, 384);
        return Unit.a;
    }
}
