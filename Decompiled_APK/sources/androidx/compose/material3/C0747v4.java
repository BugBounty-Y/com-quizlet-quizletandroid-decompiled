package androidx.compose.material3;

import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.v4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0747v4 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ArrayList b;
    public final /* synthetic */ androidx.compose.ui.layout.f0 c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ C0752w3 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ ArrayList g;
    public final /* synthetic */ long h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ androidx.compose.runtime.internal.d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0747v4(int i, ArrayList arrayList, androidx.compose.ui.layout.f0 f0Var, androidx.compose.runtime.internal.d dVar, C0752w3 c0752w3, int i2, ArrayList arrayList2, long j, int i3, int i4, androidx.compose.runtime.internal.d dVar2) {
        super(1);
        this.a = i;
        this.b = arrayList;
        this.c = f0Var;
        this.d = dVar;
        this.e = c0752w3;
        this.f = i2;
        this.g = arrayList2;
        this.h = j;
        this.i = i3;
        this.j = i4;
        this.k = dVar2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.layout.f0 f0Var;
        int i;
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = this.b;
        int size = arrayList2.size();
        int i2 = this.a;
        int i3 = 0;
        int i4 = i2;
        while (true) {
            f0Var = this.c;
            if (i3 >= size) {
                break;
            }
            androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) arrayList2.get(i3);
            androidx.compose.ui.layout.V.f(v, w, i4, 0);
            arrayList.add(new C0714r4(f0Var.O(i4), f0Var.O(w.a), ((androidx.compose.ui.unit.e) this.g.get(i3)).a));
            i4 += w.a;
            i3++;
        }
        List listN = f0Var.n(EnumC0771z4.b, this.d);
        int size2 = listN.size();
        int i5 = 0;
        while (true) {
            i = this.j;
            if (i5 >= size2) {
                break;
            }
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) listN.get(i5);
            int i6 = this.i;
            androidx.compose.ui.layout.W wB = j.B(androidx.compose.ui.unit.a.a(this.h, i6, i6, 0, 0, 8));
            androidx.compose.ui.layout.V.f(v, wB, 0, i - wB.b);
            i5++;
        }
        List listN2 = f0Var.n(EnumC0771z4.c, new androidx.compose.runtime.internal.d(true, 1734082948, new androidx.compose.foundation.contextmenu.i(20, this.k, arrayList)));
        int size3 = listN2.size();
        for (int i7 = 0; i7 < size3; i7++) {
            androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) listN2.get(i7);
            int i8 = this.i;
            if (i8 < 0 || i < 0) {
                O5.e("width(" + i8 + ") and height(" + i + ") must be >= 0");
                throw null;
            }
            androidx.compose.ui.layout.V.f(v, j2.B(L5.m(i8, i8, i, i)), 0, 0);
        }
        C0752w3 c0752w3 = this.e;
        Integer num = c0752w3.c;
        int i9 = this.f;
        if (num == null || num.intValue() != i9) {
            c0752w3.c = Integer.valueOf(i9);
            C0714r4 c0714r4 = (C0714r4) CollectionsKt.O(i9, arrayList);
            if (c0714r4 != null) {
                C0714r4 c0714r42 = (C0714r4) CollectionsKt.U(arrayList);
                int iM0 = f0Var.m0(c0714r42.a + c0714r42.b) + i2;
                androidx.compose.foundation.N0 n0 = c0752w3.a;
                int iF = iM0 - n0.f();
                int iM02 = f0Var.m0(c0714r4.a) - ((iF / 2) - (f0Var.m0(c0714r4.b) / 2));
                int i10 = iM0 - iF;
                if (i10 < 0) {
                    i10 = 0;
                }
                int iC = kotlin.ranges.l.c(iM02, 0, i10);
                if (n0.g() != iC) {
                    kotlinx.coroutines.E.A(c0752w3.b, null, null, new C0746v3(c0752w3, iC, null), 3);
                }
            }
        }
        return Unit.a;
    }
}
