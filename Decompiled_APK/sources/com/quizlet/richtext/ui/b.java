package com.quizlet.richtext.ui;

import androidx.compose.foundation.layout.C0420z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.text.C0982b;
import androidx.compose.ui.text.L;
import androidx.compose.ui.unit.m;
import androidx.glance.appwidget.protobuf.Z;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public final /* synthetic */ androidx.compose.ui.unit.b j;
    public final /* synthetic */ String k;
    public final /* synthetic */ C0420z l;
    public final /* synthetic */ float m;
    public final /* synthetic */ androidx.compose.ui.text.font.i n;
    public final /* synthetic */ InterfaceC0773a0 o;
    public final /* synthetic */ InterfaceC0773a0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(androidx.compose.ui.unit.b bVar, String str, C0420z c0420z, float f, androidx.compose.ui.text.font.i iVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, h hVar) {
        super(2, hVar);
        this.j = bVar;
        this.k = str;
        this.l = c0420z;
        this.m = f;
        this.n = iVar;
        this.o = interfaceC0773a0;
        this.p = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.j, this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        float fO;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        InterfaceC0773a0 interfaceC0773a0 = this.o;
        L textStyle = (L) interfaceC0773a0.getValue();
        C0420z c0420z = this.l;
        float fB = c0420z.b();
        androidx.compose.ui.unit.b density = this.j;
        float fC0 = density.c0(fB);
        long j = c0420z.b;
        if (androidx.compose.ui.unit.a.c(j)) {
            fO = c0420z.a.O(androidx.compose.ui.unit.a.g(j));
        } else {
            fO = Float.POSITIVE_INFINITY;
        }
        float fC02 = density.c0(fO);
        String text = this.k;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(textStyle, "textStyle");
        Intrinsics.checkNotNullParameter(density, "density");
        androidx.compose.ui.text.font.i fontFamilyResolver = this.n;
        Intrinsics.checkNotNullParameter(fontFamilyResolver, "fontFamilyResolver");
        int i = (int) fC0;
        int i2 = 13;
        String str = text;
        C0982b c0982bA = AbstractC3178j5.a(str, textStyle, L5.b(i, 0, 13), density, fontFamilyResolver, null, 0, DtbConstants.DEFAULT_PLAYER_HEIGHT);
        float fC = m.c(textStyle.a.b);
        L l = textStyle;
        while (c0982bA.b() > fC02) {
            float f = this.m;
            if (fC <= f) {
                break;
            }
            float f2 = fC * 0.65f;
            if (f2 >= f) {
                f = f2;
            }
            L lB = L.b(l, 0L, S5.i(4294967296L, f), null, null, 0L, 0, 0L, null, 16777213);
            androidx.compose.ui.unit.b bVar = density;
            androidx.compose.ui.text.font.i iVar = fontFamilyResolver;
            String str2 = str;
            C0982b c0982bA2 = AbstractC3178j5.a(str2, lB, L5.b(i, 0, i2), bVar, iVar, null, 0, DtbConstants.DEFAULT_PLAYER_HEIGHT);
            i2 = i2;
            str = str2;
            l = lB;
            c0982bA = c0982bA2;
            density = bVar;
            fontFamilyResolver = iVar;
            fC = f;
        }
        interfaceC0773a0.setValue(l);
        this.p.setValue(Boolean.TRUE);
        return Unit.a;
    }
}
