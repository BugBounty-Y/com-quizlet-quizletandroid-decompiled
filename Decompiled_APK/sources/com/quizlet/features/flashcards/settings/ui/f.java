package com.quizlet.features.flashcards.settings.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3218o0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ q c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;

    public /* synthetic */ f(androidx.compose.ui.graphics.painter.b bVar, int i, int i2, boolean z, q qVar, Function1 function1, int i3) {
        this.g = bVar;
        this.e = i;
        this.f = i2;
        this.b = z;
        this.c = qVar;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                q qVar = this.c;
                Function1 function1 = this.d;
                AbstractC3218o0.a((androidx.compose.ui.graphics.painter.b) this.g, this.e, this.f, this.b, qVar, function1, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                Function1 function12 = (Function1) this.g;
                AbstractC3106b5.a(this.b, this.c, this.d, function12, (InterfaceC0806l) obj, iH2, this.f);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(boolean z, q qVar, Function1 function1, Function1 function12, int i, int i2) {
        this.b = z;
        this.c = qVar;
        this.d = function1;
        this.g = function12;
        this.e = i;
        this.f = i2;
    }
}
