package com.quizlet.ui.compose;

import androidx.compose.animation.core.C0238e;
import com.google.android.gms.internal.mlkit_vision_barcode.B5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes3.dex */
public final /* synthetic */ class F extends C4956o implements Function0 {
    public final /* synthetic */ kotlinx.coroutines.C a;
    public final /* synthetic */ C0238e b;
    public final /* synthetic */ C0238e c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ Function1 e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(kotlinx.coroutines.C c, C0238e c0238e, C0238e c0238e2, Function1 function1, Function1 function12) {
        super(0, AbstractC4958q.class, "animateToOriginalPlace", "SwappableContainer$animateToOriginalPlace(Lkotlinx/coroutines/CoroutineScope;Landroidx/compose/animation/core/Animatable;Landroidx/compose/animation/core/Animatable;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", 0);
        this.a = c;
        this.b = c0238e;
        this.c = c0238e2;
        this.d = function1;
        this.e = function12;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        B5.c(this.a, this.b, this.c, this.d, this.e);
        return Unit.a;
    }
}
