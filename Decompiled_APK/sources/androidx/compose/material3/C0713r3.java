package androidx.compose.material3;

import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.r3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0713r3 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ ArrayList a;
    public final /* synthetic */ ArrayList b;
    public final /* synthetic */ ArrayList c;
    public final /* synthetic */ ArrayList d;
    public final /* synthetic */ C0676l1 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 h;
    public final /* synthetic */ androidx.compose.ui.layout.f0 i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ Integer l;
    public final /* synthetic */ ArrayList m;
    public final /* synthetic */ Integer n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0713r3(ArrayList arrayList, ArrayList arrayList2, ArrayList arrayList3, ArrayList arrayList4, C0676l1 c0676l1, int i, int i2, androidx.compose.foundation.layout.R0 r0, androidx.compose.ui.layout.f0 f0Var, int i3, int i4, Integer num, ArrayList arrayList5, Integer num2) {
        super(1);
        this.a = arrayList;
        this.b = arrayList2;
        this.c = arrayList3;
        this.d = arrayList4;
        this.e = c0676l1;
        this.f = i;
        this.g = i2;
        this.h = r0;
        this.i = f0Var;
        this.j = i3;
        this.k = i4;
        this.l = num;
        this.m = arrayList5;
        this.n = num2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i;
        androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
        ArrayList arrayList = this.a;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            androidx.compose.ui.layout.V.d(v, (androidx.compose.ui.layout.W) arrayList.get(i2), 0, 0);
        }
        ArrayList arrayList2 = this.b;
        int size2 = arrayList2.size();
        for (int i3 = 0; i3 < size2; i3++) {
            androidx.compose.ui.layout.V.d(v, (androidx.compose.ui.layout.W) arrayList2.get(i3), 0, 0);
        }
        ArrayList arrayList3 = this.c;
        int size3 = arrayList3.size();
        int i4 = 0;
        while (true) {
            i = this.j;
            if (i4 >= size3) {
                break;
            }
            androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) arrayList3.get(i4);
            int i5 = (this.f - this.g) / 2;
            androidx.compose.ui.layout.f0 f0Var = this.i;
            androidx.compose.ui.layout.V.d(v, w, this.h.d(f0Var, f0Var.getLayoutDirection()) + i5, i - this.k);
            i4++;
        }
        ArrayList arrayList4 = this.d;
        int size4 = arrayList4.size();
        for (int i6 = 0; i6 < size4; i6++) {
            androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) arrayList4.get(i6);
            Integer num = this.l;
            androidx.compose.ui.layout.V.d(v, w2, 0, i - (num != null ? num.intValue() : 0));
        }
        C0676l1 c0676l1 = this.e;
        if (c0676l1 != null) {
            ArrayList arrayList5 = this.m;
            int size5 = arrayList5.size();
            for (int i7 = 0; i7 < size5; i7++) {
                androidx.compose.ui.layout.W w3 = (androidx.compose.ui.layout.W) arrayList5.get(i7);
                Integer num2 = this.n;
                Intrinsics.d(num2);
                androidx.compose.ui.layout.V.d(v, w3, c0676l1.a, i - num2.intValue());
            }
        }
        return Unit.a;
    }
}
