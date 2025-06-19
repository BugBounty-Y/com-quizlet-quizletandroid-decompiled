package androidx.compose.foundation.text;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.InterfaceC0815p0;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.input.C0998a;
import androidx.compose.ui.text.input.C1003f;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0492h0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ D(C0492h0 c0492h0, int i) {
        super(1);
        this.a = i;
        this.b = c0492h0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Function1 function1;
        Unit unit;
        androidx.compose.ui.platform.Q0 q0;
        boolean z = false;
        Unit unit2 = null;
        C0492h0 c0492h0 = this.b;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.r rVar = (androidx.compose.ui.layout.r) obj;
                K0 k0D = c0492h0.d();
                if (k0D != null) {
                    k0D.c = rVar;
                }
                return Unit.a;
            case 1:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                ((androidx.compose.runtime.L0) c0492h0.q).setValue(bool);
                return Unit.a;
            case 2:
                List list = (List) obj;
                if (c0492h0.d() != null) {
                    K0 k0D2 = c0492h0.d();
                    Intrinsics.d(k0D2);
                    list.add(k0D2.a);
                    z = true;
                }
                return Boolean.valueOf(z);
            case 3:
                C0995g c0995g = (C0995g) obj;
                androidx.compose.ui.text.input.H h = c0492h0.e;
                D d = c0492h0.t;
                if (h != null) {
                    androidx.compose.ui.text.input.A aF = c0492h0.d.f(kotlin.collections.B.j(new C1003f(), new C0998a(c0995g, 1)));
                    h.a(null, aF);
                    d.invoke(aF);
                    unit2 = Unit.a;
                }
                if (unit2 == null) {
                    String str = c0995g.a;
                    int length = str.length();
                    d.invoke(new androidx.compose.ui.text.input.A(4, AbstractC3205m5.c(length, length), str));
                }
                return Boolean.TRUE;
            case 4:
                int i = ((androidx.compose.ui.text.input.l) obj).a;
                C0486e0 c0486e0 = c0492h0.r;
                c0486e0.getClass();
                if (i == 7) {
                    function1 = c0486e0.a().a;
                } else if (i == 2) {
                    function1 = c0486e0.a().b;
                } else if (i == 6) {
                    function1 = c0486e0.a().c;
                } else if (i == 5) {
                    function1 = c0486e0.a().d;
                } else if (i == 3) {
                    function1 = c0486e0.a().e;
                } else if (i == 4) {
                    function1 = c0486e0.a().f;
                } else {
                    if (i != 1 && i != 0) {
                        throw new IllegalStateException("invalid ImeAction");
                    }
                    function1 = null;
                }
                if (function1 != null) {
                    function1.invoke(c0486e0);
                    unit = Unit.a;
                } else {
                    unit = null;
                }
                if (unit == null) {
                    if (i == 6) {
                        androidx.compose.ui.focus.h hVar = c0486e0.c;
                        if (hVar == null) {
                            Intrinsics.m("focusManager");
                            throw null;
                        }
                        ((androidx.compose.ui.focus.j) hVar).e(1);
                    } else if (i == 5) {
                        androidx.compose.ui.focus.h hVar2 = c0486e0.c;
                        if (hVar2 == null) {
                            Intrinsics.m("focusManager");
                            throw null;
                        }
                        ((androidx.compose.ui.focus.j) hVar2).e(2);
                    } else if (i == 7 && (q0 = c0486e0.a) != null) {
                        ((C0957n0) q0).a();
                    }
                }
                return Unit.a;
            default:
                androidx.compose.ui.text.input.A a = (androidx.compose.ui.text.input.A) obj;
                String str2 = a.a.a;
                C0995g c0995g2 = c0492h0.j;
                if (!Intrinsics.b(str2, c0995g2 != null ? c0995g2.a : null)) {
                    ((androidx.compose.runtime.L0) c0492h0.k).setValue(V.a);
                }
                long j = androidx.compose.ui.text.K.b;
                c0492h0.f(j);
                c0492h0.e(j);
                c0492h0.s.invoke(a);
                C0813o0 c0813o0 = c0492h0.b;
                InterfaceC0815p0 interfaceC0815p0 = c0813o0.b;
                if (interfaceC0815p0 != null) {
                    interfaceC0815p0.b(c0813o0, null);
                }
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(C0492h0 c0492h0, androidx.compose.ui.semantics.v vVar) {
        super(1);
        this.a = 3;
        this.b = c0492h0;
    }
}
