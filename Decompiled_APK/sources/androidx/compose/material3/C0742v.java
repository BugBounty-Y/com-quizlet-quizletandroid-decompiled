package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0742v extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.ui.layout.W a;
    public final /* synthetic */ int b;
    public final /* synthetic */ androidx.compose.ui.layout.W c;
    public final /* synthetic */ InterfaceC0388h d;
    public final /* synthetic */ long e;
    public final /* synthetic */ androidx.compose.ui.layout.W f;
    public final /* synthetic */ androidx.compose.ui.layout.M g;
    public final /* synthetic */ InterfaceC0394k h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0742v(androidx.compose.ui.layout.W w, int i, androidx.compose.ui.layout.W w2, InterfaceC0388h interfaceC0388h, long j, androidx.compose.ui.layout.W w3, androidx.compose.ui.layout.M m, InterfaceC0394k interfaceC0394k, int i2, int i3) {
        super(1);
        this.a = w;
        this.b = i;
        this.c = w2;
        this.d = interfaceC0388h;
        this.e = j;
        this.f = w3;
        this.g = m;
        this.h = interfaceC0394k;
        this.i = i2;
        this.j = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int iMax;
        int iH;
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        androidx.compose.ui.layout.W w = this.a;
        int i = w.b;
        int i2 = this.b;
        int iMax2 = 0;
        androidx.compose.ui.layout.V.f(v, w, 0, (i2 - i) / 2);
        C0386g c0386g = AbstractC0398m.e;
        InterfaceC0388h interfaceC0388h = this.d;
        boolean zB = Intrinsics.b(interfaceC0388h, c0386g);
        androidx.compose.ui.layout.W w2 = this.c;
        androidx.compose.ui.layout.W w3 = this.f;
        long j = this.e;
        if (zB) {
            int iH2 = androidx.compose.ui.unit.a.h(j);
            int i3 = w2.a;
            iMax = (iH2 - i3) / 2;
            int i4 = w.a;
            if (iMax < i4) {
                iH = i4 - iMax;
            } else if (i3 + iMax > androidx.compose.ui.unit.a.h(j) - w3.a) {
                iH = (androidx.compose.ui.unit.a.h(j) - w3.a) - (w2.a + iMax);
            }
            iMax += iH;
        } else if (Intrinsics.b(interfaceC0388h, AbstractC0398m.b)) {
            iMax = (androidx.compose.ui.unit.a.h(j) - w2.a) - w3.a;
        } else {
            iMax = Math.max(this.g.m0(D.g), w.a);
        }
        InterfaceC0394k interfaceC0394k = this.h;
        if (Intrinsics.b(interfaceC0394k, c0386g)) {
            iMax2 = (i2 - w2.b) / 2;
        } else if (Intrinsics.b(interfaceC0394k, AbstractC0398m.d)) {
            int i5 = this.i;
            if (i5 == 0) {
                iMax2 = i2 - w2.b;
            } else {
                int i6 = w2.b;
                int iG = i5 - (i6 - this.j);
                int i7 = i6 + iG;
                if (i7 > androidx.compose.ui.unit.a.g(j)) {
                    iG -= i7 - androidx.compose.ui.unit.a.g(j);
                }
                iMax2 = (i2 - w2.b) - Math.max(0, iG);
            }
        }
        androidx.compose.ui.layout.V.f(v, w2, iMax, iMax2);
        androidx.compose.ui.layout.V.f(v, w3, androidx.compose.ui.unit.a.h(j) - w3.a, (i2 - w3.b) / 2);
        return Unit.a;
    }
}
