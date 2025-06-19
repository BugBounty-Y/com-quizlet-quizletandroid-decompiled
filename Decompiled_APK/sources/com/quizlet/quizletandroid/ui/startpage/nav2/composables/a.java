package com.quizlet.quizletandroid.ui.startpage.nav2.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.I;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a = 2;
    public final /* synthetic */ q b;
    public final /* synthetic */ float c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    public /* synthetic */ a(float f, q qVar, I i, int i2) {
        this.c = f;
        this.b = qVar;
        this.e = i;
        this.d = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(385);
                Function2 function2 = (Function2) this.e;
                Y5.a(this.b, this.c, function2, (InterfaceC0806l) obj, iH, this.d);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                com.quizlet.ui.states.a aVar = (com.quizlet.ui.states.a) this.e;
                float f = this.c;
                AbstractC3274u5.e(this.b, aVar, f, (InterfaceC0806l) obj, iH2, this.d);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.d | 1);
                q qVar = this.b;
                I i = (I) this.e;
                S5.d(this.c, qVar, i, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(q qVar, float f, Function2 function2, int i, int i2) {
        this.b = qVar;
        this.c = f;
        this.e = function2;
        this.d = i2;
    }

    public /* synthetic */ a(q qVar, com.quizlet.ui.states.a aVar, float f, int i, int i2) {
        this.b = qVar;
        this.e = aVar;
        this.c = f;
        this.d = i2;
    }
}
