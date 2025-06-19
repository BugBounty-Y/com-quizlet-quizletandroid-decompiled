package com.airbnb.lottie.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.InterfaceC0889j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class i extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.airbnb.lottie.h b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ androidx.compose.ui.d e;
    public final /* synthetic */ InterfaceC0889j f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ i(com.airbnb.lottie.h hVar, Function0 function0, androidx.compose.ui.q qVar, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, int i, int i2, int i3) {
        super(2);
        this.a = i3;
        this.b = hVar;
        this.c = function0;
        this.d = qVar;
        this.e = dVar;
        this.f = interfaceC0889j;
        this.g = i;
        this.h = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.g | 1);
                int iH2 = C0776c.H(this.h);
                androidx.compose.ui.d dVar = this.e;
                InterfaceC0889j interfaceC0889j = this.f;
                AbstractC3515q.b(this.b, this.c, this.d, dVar, interfaceC0889j, (InterfaceC0806l) obj, iH, iH2);
                break;
            default:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.g | 1);
                int iH4 = C0776c.H(this.h);
                androidx.compose.ui.q qVar = this.d;
                androidx.compose.ui.d dVar2 = this.e;
                InterfaceC0889j interfaceC0889j2 = this.f;
                AbstractC3515q.b(this.b, this.c, qVar, dVar2, interfaceC0889j2, (InterfaceC0806l) obj, iH3, iH4);
                break;
        }
        return Unit.a;
    }
}
