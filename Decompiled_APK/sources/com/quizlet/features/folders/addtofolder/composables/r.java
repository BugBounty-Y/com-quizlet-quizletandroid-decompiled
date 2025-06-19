package com.quizlet.features.folders.addtofolder.composables;

import androidx.compose.animation.F;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.B;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.focus.h b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ r(androidx.compose.ui.focus.h hVar, Function1 function1, int i) {
        this.a = i;
        this.b = hVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                F AnimatedVisibility = (F) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility, "$this$AnimatedVisibility");
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(1964333003);
                Function1 function1 = this.c;
                boolean zF = c0814p.f(function1);
                Object objI = c0814p.I();
                Object obj4 = C0804k.a;
                if (zF || objI == obj4) {
                    objI = new B(6, function1);
                    c0814p.i0(objI);
                }
                Function1 function12 = (Function1) objI;
                boolean zS = AbstractC4178x.s(c0814p, false, 1964345991, function1);
                Object objI2 = c0814p.I();
                if (zS || objI2 == obj4) {
                    objI2 = new com.quizlet.facebook.a(7, function1);
                    c0814p.i0(objI2);
                }
                Function0 function0 = (Function0) objI2;
                boolean zS2 = AbstractC4178x.s(c0814p, false, 1964341800, function1);
                Object objI3 = c0814p.I();
                if (zS2 || objI3 == obj4) {
                    objI3 = new com.quizlet.facebook.a(8, function1);
                    c0814p.i0(objI3);
                }
                Function0 function02 = (Function0) objI3;
                boolean zS3 = AbstractC4178x.s(c0814p, false, 1964337483, function1);
                Object objI4 = c0814p.I();
                if (zS3 || objI4 == obj4) {
                    objI4 = new B(7, function1);
                    c0814p.i0(objI4);
                }
                c0814p.p(false);
                O4.c(this.b, null, false, R.string.search, function12, function0, function02, (Function1) objI4, c0814p, 0, 14);
                break;
            default:
                F AnimatedVisibility2 = (F) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(AnimatedVisibility2, "$this$AnimatedVisibility");
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(1484540732);
                Function1 function13 = this.c;
                boolean zF2 = c0814p2.f(function13);
                Object objI5 = c0814p2.I();
                Object obj5 = C0804k.a;
                if (zF2 || objI5 == obj5) {
                    objI5 = new B(13, function13);
                    c0814p2.i0(objI5);
                }
                Function1 function14 = (Function1) objI5;
                boolean zS4 = AbstractC4178x.s(c0814p2, false, 1484553528, function13);
                Object objI6 = c0814p2.I();
                if (zS4 || objI6 == obj5) {
                    objI6 = new com.quizlet.facebook.a(14, function13);
                    c0814p2.i0(objI6);
                }
                Function0 function03 = (Function0) objI6;
                boolean zS5 = AbstractC4178x.s(c0814p2, false, 1484549401, function13);
                Object objI7 = c0814p2.I();
                if (zS5 || objI7 == obj5) {
                    objI7 = new com.quizlet.facebook.a(15, function13);
                    c0814p2.i0(objI7);
                }
                Function0 function04 = (Function0) objI7;
                boolean zS6 = AbstractC4178x.s(c0814p2, false, 1484545148, function13);
                Object objI8 = c0814p2.I();
                if (zS6 || objI8 == obj5) {
                    objI8 = new B(14, function13);
                    c0814p2.i0(objI8);
                }
                c0814p2.p(false);
                O4.c(this.b, null, false, 0, function14, function03, function04, (Function1) objI8, c0814p2, 0, 30);
                break;
        }
        return Unit.a;
    }
}
