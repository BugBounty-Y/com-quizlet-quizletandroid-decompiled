package androidx.activity.compose;

import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.D;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.input.internal.B;
import androidx.compose.foundation.text.input.internal.w;
import androidx.compose.foundation.text.w0;
import androidx.compose.material3.A0;
import androidx.compose.material3.Z0;
import androidx.compose.material3.internal.C0657v;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.G;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.Y0;
import androidx.compose.ui.text.K;
import androidx.compose.ui.text.input.A;
import androidx.compose.ui.window.u;
import androidx.compose.ui.window.y;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.ranges.IntRange;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class d extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(u uVar, Function0 function0, y yVar, String str, androidx.compose.ui.unit.k kVar) {
        super(1);
        this.a = 4;
        this.b = uVar;
        this.c = function0;
        this.e = yVar;
        this.d = str;
        this.f = kVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 0;
        Object obj2 = this.e;
        Object obj3 = this.c;
        Object obj4 = this.f;
        Object obj5 = this.d;
        Object obj6 = this.b;
        switch (this.a) {
            case 0:
                a aVar = (a) obj6;
                aVar.a = ((androidx.activity.result.h) obj3).c((String) obj5, (androidx.activity.result.contract.a) obj2, new b((InterfaceC0773a0) obj4, i));
                return new c(aVar, 0);
            case 1:
                G g = (G) obj;
                g.b();
                float fI = ((androidx.compose.foundation.text.input.internal.n) obj6).b.i();
                if (fI != DefinitionKt.NO_Float_VALUE) {
                    long j = ((A) obj5).b;
                    int i2 = K.c;
                    int iP = ((androidx.compose.ui.text.input.s) obj3).p((int) (j >> 32));
                    K0 k0D = ((C0492h0) obj2).d();
                    androidx.compose.ui.geometry.c cVarC = k0D != null ? k0D.a.c(iP) : new androidx.compose.ui.geometry.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
                    float fC0 = g.c0(w0.a);
                    float f = fC0 / 2;
                    float f2 = cVarC.a + f;
                    float fD = androidx.compose.ui.geometry.e.d(g.a.g()) - f;
                    if (f2 > fD) {
                        f2 = fD;
                    }
                    if (f2 >= f) {
                        f = f2;
                    }
                    androidx.compose.ui.graphics.drawscope.d.Y(g, (AbstractC0857q) obj4, Q4.c(f, cVarC.b), Q4.c(f, cVarC.d), fC0, fI, 432);
                }
                return Unit.a;
            case 2:
                B b = (B) obj;
                w wVar = ((androidx.compose.foundation.text.input.internal.g) obj3).a;
                b.h = (A) obj6;
                b.i = (androidx.compose.ui.text.input.m) obj5;
                b.c = (g) obj2;
                b.d = (D) obj4;
                b.e = wVar != null ? wVar.o : null;
                b.f = wVar != null ? wVar.p : null;
                b.g = wVar != null ? (Y0) AbstractC0910f.i(wVar, AbstractC0955m0.q) : null;
                return Unit.a;
            case 3:
                int iIntValue = ((Number) obj).intValue();
                float f3 = Z0.a;
                ((InterfaceC0773a0) obj4).setValue(Boolean.valueOf(!((Boolean) r4.getValue()).booleanValue()));
                E.A((C) obj6, null, null, new A0((androidx.compose.foundation.lazy.A) obj3, iIntValue, (IntRange) obj5, (C0657v) obj2, null), 3);
                return Unit.a;
            default:
                u uVar = (u) obj6;
                uVar.f.addView(uVar, uVar.g);
                uVar.f((Function0) obj3, (y) obj2, (String) obj5, (androidx.compose.ui.unit.k) obj4);
                return new c(uVar, 11);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(C c, InterfaceC0773a0 interfaceC0773a0, androidx.compose.foundation.lazy.A a, IntRange intRange, C0657v c0657v) {
        super(1);
        this.a = 3;
        this.b = c;
        this.f = interfaceC0773a0;
        this.c = a;
        this.d = intRange;
        this.e = c0657v;
    }
}
