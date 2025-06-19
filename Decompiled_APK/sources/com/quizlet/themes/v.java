package com.quizlet.themes;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class v implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.material3.windowsizeclass.b b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ h d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    public /* synthetic */ v(androidx.compose.material3.windowsizeclass.b bVar, boolean z, h hVar, androidx.compose.runtime.internal.d dVar, int i, int i2, int i3) {
        this.a = i3;
        this.b = bVar;
        this.c = z;
        this.d = hVar;
        this.e = dVar;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                androidx.compose.runtime.internal.d dVar = this.e;
                AbstractC3178j5.b(this.b, this.c, this.d, dVar, (InterfaceC0806l) obj, iH, this.g);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                androidx.compose.runtime.internal.d dVar2 = this.e;
                AbstractC3178j5.c(this.b, this.c, this.d, dVar2, (InterfaceC0806l) obj, iH2, this.g);
                break;
        }
        return Unit.a;
    }
}
