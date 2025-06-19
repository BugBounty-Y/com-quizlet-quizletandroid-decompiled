package com.quizlet.quizletandroid.ui.widgets;

import android.content.res.Resources;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.quizlet.data.model.B2;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D implements kotlin.jvm.functions.c {
    public final /* synthetic */ B2 a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;

    public D(B2 b2, int i, int i2, int i3) {
        this.a = b2;
        this.b = i;
        this.c = i2;
        this.d = i3;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) throws Resources.NotFoundException {
        androidx.glance.layout.g Column = (androidx.glance.layout.g) obj;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
        ((Number) obj3).intValue();
        Intrinsics.checkNotNullParameter(Column, "$this$Column");
        String strD = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.d(interfaceC0806l, R.string.jump_back_into_title);
        androidx.compose.runtime.B b = com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a;
        C0814p c0814p = (C0814p) interfaceC0806l;
        ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
        androidx.glance.text.g gVarB = com.quizlet.quizletandroid.ui.widgets.ui.theme.f.b(com.quizlet.quizletandroid.ui.widgets.ui.theme.d.b(c0814p), c0814p);
        androidx.glance.n nVar = androidx.glance.n.a;
        com.quizlet.themes.m.g.u();
        AbstractC3401v1.a(strD, AbstractC3324c.f(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 7), gVarB, 0, c0814p, 0, 8);
        B2 b2 = this.a;
        String str = b2.b;
        ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
        AbstractC3401v1.a(str, nVar, com.quizlet.quizletandroid.ui.widgets.ui.theme.d.d(c0814p), 0, c0814p, 48, 8);
        M7.a(AbstractC3332e.e(nVar), androidx.glance.layout.c.f, androidx.compose.runtime.internal.e.e(-372393604, new com.quizlet.assembly.compose.listitems.h(b2, Column, this.d, 6), c0814p), c0814p, 384, 0);
        Integer numValueOf = Integer.valueOf(this.c);
        int i = this.b;
        String strC = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.c(R.plurals.terms_progress_most_recent, i, new Object[]{numValueOf, Integer.valueOf(i)}, c0814p);
        ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(b)).getClass();
        AbstractC3401v1.a(strC, null, com.quizlet.quizletandroid.ui.widgets.ui.theme.f.b(com.quizlet.quizletandroid.ui.widgets.ui.theme.d.f(c0814p), c0814p), 0, c0814p, 0, 10);
        return Unit.a;
    }
}
