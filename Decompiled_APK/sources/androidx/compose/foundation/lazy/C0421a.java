package androidx.compose.foundation.lazy;

import androidx.compose.foundation.gestures.C0343p;
import androidx.compose.foundation.gestures.InterfaceC0314a0;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.lazy.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0421a extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ A c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ z0 h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ InterfaceC0314a0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0421a(androidx.compose.ui.q qVar, A a, z0 z0Var, Object obj, Object obj2, InterfaceC0314a0 interfaceC0314a0, boolean z, Function1 function1, int i, int i2, int i3) {
        super(2);
        this.a = i3;
        this.b = qVar;
        this.c = a;
        this.h = z0Var;
        this.i = obj;
        this.j = obj2;
        this.k = interfaceC0314a0;
        this.d = z;
        this.e = function1;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.f | 1);
                C0343p c0343p = (C0343p) this.k;
                AbstractC3137f0.a(this.b, this.c, this.h, (InterfaceC0394k) this.i, (androidx.compose.ui.g) this.j, c0343p, this.d, this.e, (InterfaceC0806l) obj, iH, this.g);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.f | 1);
                InterfaceC0314a0 interfaceC0314a0 = this.k;
                AbstractC3137f0.b(this.b, this.c, (A0) this.h, (InterfaceC0388h) this.i, (androidx.compose.ui.h) this.j, interfaceC0314a0, this.d, this.e, (InterfaceC0806l) obj, iH2, this.g);
                break;
        }
        return Unit.a;
    }
}
