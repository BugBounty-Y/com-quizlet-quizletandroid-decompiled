package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.composables;

import androidx.compose.animation.F;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.m;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements kotlin.jvm.functions.c {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                F AnimatedVisibility = (F) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility, "$this$AnimatedVisibility");
                String strD = AbstractC3106b5.d(interfaceC0806l, R.string.assistant_settings_no_sides_error);
                n nVar = n.b;
                m.g.s();
                E6.e(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), interfaceC0806l, 0);
                break;
            default:
                F AnimatedVisibility2 = (F) obj;
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility2, "$this$AnimatedVisibility");
                String strD2 = AbstractC3106b5.d(interfaceC0806l2, R.string.assistant_settings_config_invalid_question_types);
                n nVar2 = n.b;
                m.g.s();
                E6.e(strD2, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), interfaceC0806l2, 0);
                break;
        }
        return Unit.a;
    }
}
