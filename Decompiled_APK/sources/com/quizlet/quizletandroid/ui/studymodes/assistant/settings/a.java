package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.compose.animation.F;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements kotlin.jvm.functions.c {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
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
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.s();
                D6.c(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), interfaceC0806l, 0);
                break;
            default:
                F AnimatedVisibility2 = (F) obj;
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility2, "$this$AnimatedVisibility");
                String strD2 = AbstractC3106b5.d(interfaceC0806l2, R.string.assistant_settings_config_invalid_question_types);
                androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.s();
                D6.c(strD2, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), interfaceC0806l2, 0);
                break;
        }
        return Unit.a;
    }
}
