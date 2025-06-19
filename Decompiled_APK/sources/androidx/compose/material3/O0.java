package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class O0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ InterfaceC4938g i;
    public final /* synthetic */ InterfaceC4938g j;
    public final /* synthetic */ Object k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O0(androidx.compose.foundation.layout.H0 h0, boolean z, Function0 function0, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, boolean z2, androidx.compose.runtime.internal.d dVar2, boolean z3, D2 d2, int i) {
        super(2);
        this.h = h0;
        this.b = z;
        this.c = function0;
        this.i = dVar;
        this.d = qVar;
        this.e = z2;
        this.j = dVar2;
        this.f = z3;
        this.k = d2;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.g | 1);
                Function0 function0 = (Function0) this.j;
                C0699p0 c0699p0 = (C0699p0) this.k;
                Z0.h(this.d, this.b, this.e, this.f, (String) this.h, this.c, (Function0) this.i, function0, c0699p0, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.g | 1);
                D2 d2 = (D2) this.k;
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.i;
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.j;
                boolean z = this.f;
                M2.b((androidx.compose.foundation.layout.H0) this.h, this.b, this.c, dVar, this.d, this.e, dVar2, z, d2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O0(androidx.compose.ui.q qVar, boolean z, boolean z2, boolean z3, String str, Function0 function0, Function0 function02, Function0 function03, C0699p0 c0699p0, int i) {
        super(2);
        this.d = qVar;
        this.b = z;
        this.e = z2;
        this.f = z3;
        this.h = str;
        this.c = function0;
        this.i = function02;
        this.j = function03;
        this.k = c0699p0;
        this.g = i;
    }
}
