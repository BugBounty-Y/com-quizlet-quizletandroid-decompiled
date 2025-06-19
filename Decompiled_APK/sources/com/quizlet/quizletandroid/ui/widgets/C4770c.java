package com.quizlet.quizletandroid.ui.widgets;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.widgets.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4770c implements kotlin.jvm.functions.c {
    public static final C4770c b = new C4770c(0);
    public static final C4770c c = new C4770c(1);
    public static final C4770c d = new C4770c(2);
    public static final C4770c e = new C4770c(3);
    public final /* synthetic */ int a;

    public /* synthetic */ C4770c(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter((androidx.glance.layout.r) obj, "$this$Row");
                break;
            case 1:
                androidx.glance.layout.g Column = (androidx.glance.layout.g) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Column, "$this$Column");
                Column.getClass();
                org.chromium.support_lib_boundary.util.a.d(new androidx.glance.layout.m(androidx.glance.unit.d.a), interfaceC0806l, 0);
                C0814p c0814p = (C0814p) interfaceC0806l;
                if (Float.compare(androidx.compose.ui.unit.g.a(((androidx.compose.ui.unit.g) c0814p.j(androidx.glance.j.a)).a), 200) >= 0) {
                    org.chromium.support_lib_boundary.util.a.c(c0814p, 0);
                }
                break;
            case 2:
                androidx.glance.layout.r Row = (androidx.glance.layout.r) obj;
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Row, "$this$Row");
                androidx.glance.a aVar = new androidx.glance.a(R.drawable.ic_sys_search);
                String strD = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.d(interfaceC0806l2, R.string.search);
                androidx.glance.f fVar = new androidx.glance.f(new androidx.glance.s(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.b(h.a, interfaceC0806l2)));
                C0814p c0814p2 = (C0814p) interfaceC0806l2;
                androidx.glance.layout.t tVar = new androidx.glance.layout.t(new androidx.glance.unit.c(androidx.compose.ui.unit.g.b(((androidx.compose.ui.unit.g) c0814p2.j(androidx.glance.j.a)).a) / 5));
                c0814p2.X(-1852200100);
                Object objI = c0814p2.I();
                if (objI == C0804k.a) {
                    objI = new com.quizlet.quizletandroid.ui.login.z(19);
                    c0814p2.i0(objI);
                }
                c0814p2.p(false);
                AbstractC3189k7.c(aVar, strD, AbstractC3340g.c(tVar, (Function1) objI), 0, fVar, c0814p2, 32768, 8);
                String strD2 = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.d(c0814p2, R.string.search_for_set);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p2.j(com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a)).getClass();
                androidx.glance.text.g gVarA = androidx.glance.text.g.a(com.quizlet.quizletandroid.ui.widgets.ui.theme.d.e(c0814p2), com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.b(i.a, c0814p2), null, 126);
                Row.getClass();
                androidx.glance.layout.t tVar2 = new androidx.glance.layout.t(androidx.glance.unit.d.a);
                com.quizlet.themes.m.g.u();
                AbstractC3401v1.a(strD2, AbstractC3324c.f(tVar2, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), gVarA, 0, c0814p2, 0, 8);
                break;
            default:
                androidx.glance.appwidget.lazy.f item = (androidx.glance.appwidget.lazy.f) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(item, "$this$item");
                androidx.glance.p pVarD = AbstractC3332e.d(androidx.glance.n.a);
                Intrinsics.checkNotNullParameter(com.quizlet.themes.m.g, "<this>");
                AbstractC3336f.b(AbstractC3332e.f(pVarD, 12), (InterfaceC0806l) obj2, 0);
                break;
        }
        return Unit.a;
    }
}
