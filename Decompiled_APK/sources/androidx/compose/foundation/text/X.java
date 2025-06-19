package androidx.compose.foundation.text;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.material3.AbstractC0625h;
import androidx.compose.ui.layout.InterfaceC0883d;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class X extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ X(int i, int i2, Object obj, Object obj2, Object obj3) {
        super(1);
        this.a = i2;
        this.b = obj;
        this.e = obj2;
        this.c = obj3;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                Y y = (Y) this.e;
                int i = y.c;
                K0 k0 = (K0) y.e.invoke();
                androidx.compose.ui.text.H h = k0 != null ? k0.a : null;
                androidx.compose.ui.layout.M m = (androidx.compose.ui.layout.M) this.b;
                boolean z = m.getLayoutDirection() == androidx.compose.ui.unit.k.b;
                androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) this.c;
                androidx.compose.ui.geometry.c cVarL = AbstractC0484d0.l(m, i, y.d, h, z, w.a);
                EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
                int i2 = w.a;
                I0 i0 = y.b;
                i0.b(enumC0320d0, cVarL, this.d, i2);
                androidx.compose.ui.layout.V.f(v, w, Math.round(-i0.a()), 0);
                return Unit.a;
            case 1:
                androidx.compose.ui.layout.V v2 = (androidx.compose.ui.layout.V) obj;
                S0 s0 = (S0) this.e;
                int i3 = s0.c;
                K0 k02 = (K0) s0.e.invoke();
                androidx.compose.ui.text.H h2 = k02 != null ? k02.a : null;
                androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) this.c;
                androidx.compose.ui.geometry.c cVarL2 = AbstractC0484d0.l((androidx.compose.ui.layout.M) this.b, i3, s0.d, h2, false, w2.a);
                EnumC0320d0 enumC0320d02 = EnumC0320d0.a;
                int i4 = w2.b;
                I0 i02 = s0.b;
                i02.b(enumC0320d02, cVarL2, this.d, i4);
                androidx.compose.ui.layout.V.f(v2, w2, 0, Math.round(-i02.a()));
                return Unit.a;
            case 2:
                androidx.compose.ui.layout.V v3 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList = (ArrayList) this.e;
                int size = arrayList.size();
                for (int i5 = 0; i5 < size; i5++) {
                    List list = (List) arrayList.get(i5);
                    int size2 = list.size();
                    int[] iArr = new int[size2];
                    int i6 = 0;
                    while (true) {
                        androidx.compose.ui.layout.M m2 = (androidx.compose.ui.layout.M) this.b;
                        if (i6 < size2) {
                            iArr[i6] = ((androidx.compose.ui.layout.W) list.get(i6)).a + (i6 < kotlin.collections.B.i(list) ? m2.m0(AbstractC0625h.c) : 0);
                            i6++;
                        } else {
                            C0380d c0380d = AbstractC0398m.b;
                            int[] iArr2 = new int[size2];
                            for (int i7 = 0; i7 < size2; i7++) {
                                iArr2[i7] = 0;
                            }
                            c0380d.c(m2, this.d, iArr, m2.getLayoutDirection(), iArr2);
                            int size3 = list.size();
                            for (int i8 = 0; i8 < size3; i8++) {
                                androidx.compose.ui.layout.V.d(v3, (androidx.compose.ui.layout.W) list.get(i8), iArr2[i8], ((Number) ((ArrayList) this.c).get(i5)).intValue());
                            }
                        }
                    }
                }
                return Unit.a;
            case 3:
                if (obj == ((androidx.compose.runtime.E) this.b)) {
                    throw new IllegalStateException("A derived state calculation cannot read itself");
                }
                if (obj instanceof androidx.compose.runtime.snapshots.z) {
                    int i9 = ((androidx.compose.runtime.internal.f) this.e).a - this.d;
                    androidx.collection.C c = (androidx.collection.C) this.c;
                    int iC = c.c(obj);
                    c.g(Math.min(i9, iC >= 0 ? c.c[iC] : SubsamplingScaleImageView.TILE_SIZE_AUTO), obj);
                }
                return Unit.a;
            case 4:
                InterfaceC0883d interfaceC0883d = (InterfaceC0883d) obj;
                boolean zL = androidx.compose.ui.focus.a.L((androidx.compose.ui.focus.t) this.b, (androidx.compose.ui.focus.t) this.e, this.d, (androidx.activity.compose.g) this.c);
                Boolean boolValueOf = Boolean.valueOf(zL);
                if (zL || !interfaceC0883d.a()) {
                    return boolValueOf;
                }
                return null;
            default:
                InterfaceC0883d interfaceC0883d2 = (InterfaceC0883d) obj;
                boolean zK = androidx.compose.ui.focus.a.K(this.d, (androidx.activity.compose.g) this.c, (androidx.compose.ui.focus.t) this.b, (androidx.compose.ui.geometry.c) this.e);
                Boolean boolValueOf2 = Boolean.valueOf(zK);
                if (zK || !interfaceC0883d2.a()) {
                    return boolValueOf2;
                }
                return null;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ X(androidx.compose.ui.focus.t tVar, Object obj, int i, androidx.activity.compose.g gVar, int i2) {
        super(1);
        this.a = i2;
        this.b = tVar;
        this.e = obj;
        this.d = i;
        this.c = gVar;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(ArrayList arrayList, androidx.compose.ui.layout.M m, int i, ArrayList arrayList2) {
        super(1);
        this.a = 2;
        float f = AbstractC0625h.a;
        this.e = arrayList;
        this.b = m;
        this.d = i;
        this.c = arrayList2;
    }
}
