package androidx.compose.foundation.pager;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3182k0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3191l0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.pager.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0467f extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ C0466e b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ A0 d;
    public final /* synthetic */ l e;
    public final /* synthetic */ int f;
    public final /* synthetic */ float g;
    public final /* synthetic */ androidx.compose.ui.h h;
    public final /* synthetic */ androidx.compose.foundation.gestures.snapping.h i;
    public final /* synthetic */ boolean j;
    public final /* synthetic */ C0462a k;
    public final /* synthetic */ androidx.compose.foundation.gestures.snapping.n l;
    public final /* synthetic */ androidx.compose.runtime.internal.d m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0467f(C0466e c0466e, androidx.compose.ui.q qVar, A0 a0, l lVar, int i, float f, androidx.compose.ui.h hVar, androidx.compose.foundation.gestures.snapping.h hVar2, boolean z, C0462a c0462a, androidx.compose.foundation.gestures.snapping.n nVar, androidx.compose.runtime.internal.d dVar, int i2, int i3) {
        super(2);
        this.b = c0466e;
        this.c = qVar;
        this.d = a0;
        this.e = lVar;
        this.f = i;
        this.g = f;
        this.h = hVar;
        this.i = hVar2;
        this.j = z;
        this.k = c0462a;
        this.l = nVar;
        this.m = dVar;
        this.n = i2;
        this.o = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.n | 1);
                int iH2 = C0776c.H(this.o);
                androidx.compose.runtime.internal.d dVar = this.m;
                C0462a c0462a = this.k;
                androidx.compose.ui.h hVar = this.h;
                androidx.compose.ui.q qVar = this.c;
                C0466e c0466e = this.b;
                A0 a0 = this.d;
                androidx.compose.foundation.gestures.snapping.h hVar2 = this.i;
                boolean z = this.j;
                int i = this.f;
                AbstractC3182k0.b(this.g, i, iH, iH2, hVar2, this.l, a0, c0462a, c0466e, this.e, interfaceC0806l, dVar, hVar, qVar, z);
                break;
            default:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.n | 1);
                androidx.compose.runtime.internal.d dVar2 = this.m;
                C0462a c0462a2 = this.k;
                int i2 = this.o;
                C0466e c0466e2 = this.b;
                androidx.compose.ui.q qVar2 = this.c;
                A0 a02 = this.d;
                l lVar = this.e;
                int i3 = this.f;
                float f = this.g;
                androidx.compose.ui.h hVar3 = this.h;
                AbstractC3191l0.a(f, i3, iH3, i2, this.i, this.l, a02, c0462a2, c0466e2, lVar, interfaceC0806l, dVar2, hVar3, qVar2, this.j);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0467f(androidx.compose.ui.q qVar, C0466e c0466e, A0 a0, androidx.compose.foundation.gestures.snapping.h hVar, boolean z, int i, float f, l lVar, C0462a c0462a, androidx.compose.ui.h hVar2, androidx.compose.foundation.gestures.snapping.n nVar, androidx.compose.runtime.internal.d dVar, int i2, int i3) {
        super(2);
        this.c = qVar;
        this.b = c0466e;
        this.d = a0;
        this.i = hVar;
        this.j = z;
        this.f = i;
        this.g = f;
        this.e = lVar;
        this.k = c0462a;
        this.h = hVar2;
        this.l = nVar;
        this.m = dVar;
        this.n = i2;
        this.o = i3;
    }
}
