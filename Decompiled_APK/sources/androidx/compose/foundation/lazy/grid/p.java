package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.lazy.layout.E;
import androidx.compose.foundation.pager.C0472k;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class p extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ArrayList b;
    public final /* synthetic */ InterfaceC0773a0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(ArrayList arrayList, InterfaceC0773a0 interfaceC0773a0, int i) {
        super(1);
        this.a = i;
        this.b = arrayList;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ArrayList arrayList;
        int i;
        androidx.compose.ui.graphics.layer.b bVar;
        int i2;
        int i3;
        switch (this.a) {
            case 0:
                V v = (V) obj;
                ArrayList arrayList2 = this.b;
                int size = arrayList2.size();
                for (int i4 = 0; i4 < size; i4++) {
                    r rVar = (r) arrayList2.get(i4);
                    if (rVar.p == Integer.MIN_VALUE) {
                        throw new IllegalArgumentException("position() should be called first");
                    }
                    List list = rVar.g;
                    int size2 = list.size();
                    int i5 = 0;
                    while (i5 < size2) {
                        W w = (W) list.get(i5);
                        int i6 = rVar.q - w.b;
                        int i7 = rVar.r;
                        long j = rVar.t;
                        E eA = rVar.j.a(i5, rVar.b);
                        if (eA != null) {
                            arrayList = arrayList2;
                            i = size;
                            long jD = androidx.compose.ui.unit.h.d(j, ((androidx.compose.ui.unit.h) ((L0) eA.q).getValue()).a);
                            int i8 = (int) (j & 4294967295L);
                            if (((i8 <= i6 && ((int) (jD & 4294967295L)) <= i6) || (i8 >= i7 && ((int) (jD & 4294967295L)) >= i7)) && ((Boolean) ((L0) eA.h).getValue()).booleanValue()) {
                                kotlinx.coroutines.E.A(eA.a, null, null, new androidx.compose.foundation.lazy.layout.A(eA, null), 3);
                            }
                            bVar = eA.n;
                            j = jD;
                        } else {
                            arrayList = arrayList2;
                            i = size;
                            bVar = null;
                        }
                        long jD2 = androidx.compose.ui.unit.h.d(j, rVar.h);
                        if (eA != null) {
                            eA.m = jD2;
                        }
                        if (bVar != null) {
                            v.getClass();
                            V.a(v, w);
                            w.r0(androidx.compose.ui.unit.h.d(jD2, w.e), DefinitionKt.NO_Float_VALUE, bVar);
                        } else {
                            V.j(v, w, jD2);
                        }
                        i5++;
                        arrayList2 = arrayList;
                        size = i;
                    }
                }
                this.c.getValue();
                return Unit.a;
            default:
                V v2 = (V) obj;
                ArrayList arrayList3 = this.b;
                int size3 = arrayList3.size();
                int i9 = 0;
                while (i9 < size3) {
                    C0472k c0472k = (C0472k) arrayList3.get(i9);
                    if (c0472k.m == Integer.MIN_VALUE) {
                        throw new IllegalArgumentException("position() should be called first");
                    }
                    List list2 = c0472k.b;
                    int size4 = list2.size();
                    int i10 = 0;
                    while (i10 < size4) {
                        W w2 = (W) list2.get(i10);
                        int i11 = i10 * 2;
                        int[] iArr = c0472k.k;
                        long jB = P5.b(iArr[i11], iArr[i11 + 1]);
                        boolean z = c0472k.h;
                        boolean z2 = c0472k.i;
                        if (z) {
                            if (z2) {
                                i2 = i9;
                                i3 = (int) (jB >> 32);
                            } else {
                                i2 = i9;
                                i3 = (c0472k.m - ((int) (jB >> 32))) - (z2 ? w2.b : w2.a);
                            }
                            jB = P5.b(i3, z2 ? (c0472k.m - ((int) (jB & 4294967295L))) - (z2 ? w2.b : w2.a) : (int) (jB & 4294967295L));
                        } else {
                            i2 = i9;
                        }
                        long jD3 = androidx.compose.ui.unit.h.d(jB, c0472k.c);
                        if (z2) {
                            V.j(v2, w2, jD3);
                        } else {
                            V.h(v2, w2, jD3);
                        }
                        i10++;
                        i9 = i2;
                    }
                    i9++;
                }
                this.c.getValue();
                return Unit.a;
        }
    }
}
