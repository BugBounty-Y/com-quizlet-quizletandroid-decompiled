package com.quizlet.assembly.compose.buttons;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3642i5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class f0 implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    public /* synthetic */ f0(androidx.compose.ui.q qVar, String str, Function0 function0, int i, int i2) {
        this.a = 0;
        this.b = str;
        this.d = qVar;
        this.c = function0;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                Function0 function0 = this.c;
                int i = this.f;
                AbstractC3642i5.b(iH, i, (InterfaceC0806l) obj, this.d, this.b, function0);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                AbstractC3253s0.c(iH2, this.f, (InterfaceC0806l) obj, this.d, this.b, this.c);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.e | 1);
                T1.b(iH3, this.f, (InterfaceC0806l) obj, this.d, this.b, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f0(String str, Function0 function0, androidx.compose.ui.q qVar, int i, int i2, int i3) {
        this.a = i3;
        this.b = str;
        this.c = function0;
        this.d = qVar;
        this.e = i;
        this.f = i2;
    }
}
