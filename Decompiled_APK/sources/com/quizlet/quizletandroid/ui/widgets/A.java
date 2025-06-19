package com.quizlet.quizletandroid.ui.widgets;

import android.content.res.Resources;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.quizlet.data.model.C2;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2 b;

    public /* synthetic */ A(C2 c2, int i) {
        this.a = i;
        this.b = c2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) throws Resources.NotFoundException {
        switch (this.a) {
            case 0:
                androidx.glance.layout.r Row = (androidx.glance.layout.r) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Row, "$this$Row");
                C2 c2 = this.b;
                String strValueOf = String.valueOf(c2.a);
                androidx.compose.runtime.B b = com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a;
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
                AbstractC3401v1.a(strValueOf, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a(com.quizlet.quizletandroid.ui.widgets.ui.theme.d.c(c0814p), c0814p), 0, c0814p, 0, 10);
                String strA = okhttp3.internal.platform.d.a(c2, c0814p);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
                androidx.glance.text.g gVarB = com.quizlet.quizletandroid.ui.widgets.ui.theme.d.b(c0814p);
                androidx.glance.n nVar = androidx.glance.n.a;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.s();
                float f = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar.w();
                AbstractC3401v1.a(strA, AbstractC3324c.f(nVar, com.quizlet.ui.resources.designsystem.generated.j.f, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 12), gVarB, 0, c0814p, 0, 8);
                break;
            default:
                androidx.glance.layout.g Column = (androidx.glance.layout.g) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Column, "$this$Column");
                C2 c22 = this.b;
                String strC = org.slf4j.helpers.k.c(okhttp3.internal.platform.d.b(c22), interfaceC0806l);
                C0814p c0814p2 = (C0814p) interfaceC0806l;
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p2.j(com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a)).getClass();
                androidx.glance.text.g gVarD = com.quizlet.quizletandroid.ui.widgets.ui.theme.d.d(c0814p2);
                androidx.glance.n nVar2 = androidx.glance.n.a;
                c0814p2.X(1272810559);
                Object objI = c0814p2.I();
                if (objI == C0804k.a) {
                    objI = new com.quizlet.quizletandroid.ui.login.z(28);
                    c0814p2.i0(objI);
                }
                c0814p2.p(false);
                AbstractC3401v1.a(strC, AbstractC3340g.c(nVar2, (Function1) objI), gVarD, 0, c0814p2, 0, 8);
                Column.getClass();
                AbstractC3328d.c(AbstractC3332e.c(new androidx.glance.layout.m(androidx.glance.unit.d.a)), 0, 1, androidx.compose.runtime.internal.e.e(-38851013, new A(c22, 0), c0814p2), c0814p2, 3072, 2);
                break;
        }
        return Unit.a;
    }
}
