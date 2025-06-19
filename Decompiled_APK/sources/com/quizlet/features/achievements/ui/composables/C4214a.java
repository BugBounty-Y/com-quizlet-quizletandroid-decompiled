package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3128e0;
import com.google.android.gms.internal.mlkit_vision_barcode.D4;
import com.google.android.gms.internal.mlkit_vision_common.J2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3666l5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K4;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.achievements.ui.composables.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4214a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;

    public /* synthetic */ C4214a(String str, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
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
                com.bumptech.glide.c.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 1:
                com.bumptech.glide.c.e(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                com.bumptech.glide.c.d(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                D4.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                J2.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 5:
                com.google.android.gms.internal.mlkit_vision_document_scanner.E.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 6:
                K4.b(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 7:
                AbstractC3634h5.b(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 8:
                AbstractC3666l5.b(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 9:
                D6.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 10:
                E6.e(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                AbstractC3128e0.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
