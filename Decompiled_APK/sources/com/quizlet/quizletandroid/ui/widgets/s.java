package com.quizlet.quizletandroid.ui.widgets;

import android.content.res.Resources;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.quizlet.data.model.B2;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ B2 b;

    public /* synthetic */ s(B2 b2, int i) {
        this.a = i;
        this.b = b2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) throws Resources.NotFoundException {
        switch (this.a) {
            case 0:
                androidx.glance.layout.g Column = (androidx.glance.layout.g) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Column, "$this$Column");
                B2 b2 = this.b;
                String str = b2.b;
                androidx.compose.runtime.B b = com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a;
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
                AbstractC3401v1.a(str, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.d.f(c0814p), 2, c0814p, 3072, 2);
                int i = b2.c;
                String strC = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.c(R.plurals.terms, i, new Object[]{Integer.valueOf(i)}, c0814p);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
                AbstractC3401v1.a(strC, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.d.b(c0814p), 0, c0814p, 0, 10);
                break;
            case 1:
                androidx.glance.layout.g Column2 = (androidx.glance.layout.g) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Column2, "$this$Column");
                B2 b22 = this.b;
                String str2 = b22.b;
                androidx.compose.runtime.B b3 = com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a;
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p2.j(b3)).getClass();
                c0814p2.X(-213172329);
                androidx.glance.text.g gVarA = com.quizlet.quizletandroid.ui.widgets.ui.theme.d.a(new androidx.compose.ui.unit.m(S5.g(14)), new androidx.glance.text.b(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), c0814p2, 4);
                c0814p2.p(false);
                AbstractC3401v1.a(str2, null, gVarA, 2, c0814p2, 3072, 2);
                int i2 = b22.c;
                String strC2 = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.c(R.plurals.terms, i2, new Object[]{Integer.valueOf(i2)}, c0814p2);
                ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p2.j(b3)).getClass();
                AbstractC3401v1.a(strC2, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.d.b(c0814p2), 0, c0814p2, 0, 10);
                break;
            default:
                androidx.glance.layout.r Row = (androidx.glance.layout.r) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(Row, "$this$Row");
                androidx.glance.n nVar = androidx.glance.n.a;
                Row.getClass();
                AbstractC3320b.a(new androidx.glance.layout.t(androidx.glance.unit.d.a), 0, androidx.compose.runtime.internal.e.e(-36889899, new s(this.b, 1), interfaceC0806l), interfaceC0806l, 3072, 6);
                androidx.glance.a aVar = new androidx.glance.a(R.drawable.ic_study_flashcards);
                String strD = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.d(interfaceC0806l, R.string.study_cards_description);
                com.quizlet.themes.m.g.u();
                AbstractC3189k7.c(aVar, strD, AbstractC3324c.f(nVar, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 0, null, interfaceC0806l, 0, 24);
                break;
        }
        return Unit.a;
    }
}
