package com.quizlet.assembly.compose.cards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3101b0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3182k0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import com.google.android.gms.internal.mlkit_vision_barcode.t7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3406w2;
import com.google.android.gms.internal.mlkit_vision_camera.M2;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.google.android.gms.internal.mlkit_vision_common.P2;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3595c6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3658k5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3746v6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;

    public /* synthetic */ d(int i, int i2, q qVar) {
        this.a = i2;
        this.b = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3658k5.c(this.b, interfaceC0806l, C0776c.H(7));
                break;
            case 1:
                C5.j(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                Q5.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                AbstractC3595c6.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                Q4.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 5:
                Q4.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 6:
                AbstractC3225o7.b(this.b, interfaceC0806l, C0776c.H(7));
                break;
            case 7:
                AbstractC3234p7.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 8:
                s7.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 9:
                t7.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 10:
                Y1.a(this.b, interfaceC0806l, C0776c.H(7));
                break;
            case 11:
                AbstractC3406w2.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 12:
                M2.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 13:
                P2.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 14:
                Y3.e(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 15:
                Y3.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 16:
                Y3.c(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 17:
                L.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 18:
                L.h(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 19:
                AbstractC3746v6.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 20:
                E6.o(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 21:
                X6.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                h7.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case EventType.AUDIO /* 23 */:
                AbstractC3101b0.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            default:
                AbstractC3182k0.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
