package com.quizlet.assembly.compose.pills;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3241q5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import com.quizlet.ui.compose.EnumC4819l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;

    public /* synthetic */ d(q qVar, long j, long j2, Object obj, int i, int i2, int i3) {
        this.a = i3;
        this.b = qVar;
        this.c = j;
        this.d = j2;
        this.g = obj;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.g;
                AbstractC3587b6.b(this.b, this.c, this.d, dVar, (InterfaceC0806l) obj, iH, this.f);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                EnumC4819l enumC4819l = (EnumC4819l) this.g;
                AbstractC3241q5.a(this.b, this.c, this.d, enumC4819l, (InterfaceC0806l) obj, iH2, this.f);
                break;
        }
        return Unit.a;
    }
}
