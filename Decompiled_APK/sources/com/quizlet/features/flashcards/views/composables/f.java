package com.quizlet.features.flashcards.views.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3261t0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ f(Function0 function0, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = function0;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.assembly.compose.components.flashcards.b it2 = (com.quizlet.assembly.compose.components.flashcards.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                AbstractC3261t0.b(this.c, this.b);
                break;
            case 1:
                com.quizlet.assembly.compose.components.flashcards.b it3 = (com.quizlet.assembly.compose.components.flashcards.b) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                InterfaceC0773a0 interfaceC0773a0 = this.c;
                interfaceC0773a0.setValue(((com.quizlet.assembly.compose.components.flashcards.b) interfaceC0773a0.getValue()).a());
                this.b.invoke();
                break;
            case 2:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                this.c.setValue(it4);
                this.b.invoke();
                break;
            case 3:
                String it5 = (String) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                this.c.setValue(it5);
                this.b.invoke();
                break;
            case 4:
                String it6 = (String) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                this.c.setValue(it6);
                this.b.invoke();
                break;
            case 5:
                String it7 = (String) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                this.c.setValue(it7);
                this.b.invoke();
                break;
            case 6:
                String it8 = (String) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                this.c.setValue(it8);
                this.b.invoke();
                break;
            case 7:
                String it9 = (String) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                this.c.setValue(it9);
                this.b.invoke();
                break;
            default:
                ((Float) obj).floatValue();
                this.c.setValue(Boolean.TRUE);
                this.b.invoke();
                break;
        }
        return Unit.a;
    }
}
