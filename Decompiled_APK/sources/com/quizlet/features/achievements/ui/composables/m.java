package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class m implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ int d;

    public /* synthetic */ m(int i, String str, androidx.compose.ui.q qVar, int i2) {
        this.a = 4;
        this.d = i;
        this.b = str;
        this.c = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.facebook.appevents.cloudbridge.c.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            case 1:
                AbstractC3214n5.b(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            case 2:
                R1.c(C0776c.H(1), this.d, interfaceC0806l, this.c, this.b);
                break;
            case 3:
                W1.K(C0776c.H(1), this.d, interfaceC0806l, this.c, this.b);
                break;
            case 4:
                int iH = C0776c.H(1);
                String str = this.b;
                AbstractC3531s4.b(this.d, iH, interfaceC0806l, this.c, str);
                break;
            case 5:
                AbstractC3722s6.b(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            case 6:
                h7.b(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            case 7:
                com.google.mlkit.common.model.a.f(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            default:
                D0.i(C0776c.H(1), this.d, interfaceC0806l, this.c, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ m(String str, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = qVar;
        this.d = i;
    }

    public /* synthetic */ m(String str, androidx.compose.ui.q qVar, int i, int i2, int i3) {
        this.a = i3;
        this.b = str;
        this.c = qVar;
        this.d = i2;
    }
}
