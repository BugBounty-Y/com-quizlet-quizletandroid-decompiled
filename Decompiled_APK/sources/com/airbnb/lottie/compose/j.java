package com.airbnb.lottie.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.InterfaceC0889j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class j extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ com.airbnb.lottie.h a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ int c;
    public final /* synthetic */ androidx.compose.ui.d d;
    public final /* synthetic */ InterfaceC0889j e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.airbnb.lottie.h hVar, androidx.compose.ui.q qVar, int i, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, int i2, int i3, int i4) {
        super(2);
        this.a = hVar;
        this.b = qVar;
        this.c = i;
        this.d = dVar;
        this.e = interfaceC0889j;
        this.f = i2;
        this.g = i3;
        this.h = i4;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        int iH2 = C0776c.H(this.g);
        InterfaceC0889j interfaceC0889j = this.e;
        AbstractC3515q.a(this.a, this.b, this.c, this.d, interfaceC0889j, (InterfaceC0806l) obj, iH, iH2, this.h);
        return Unit.a;
    }
}
