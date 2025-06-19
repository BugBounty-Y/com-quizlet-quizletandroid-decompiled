package androidx.compose.foundation.lazy;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.layout.L;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class q implements L {
    public final r a;
    public int b;
    public boolean c;
    public float d;
    public final float e;
    public final boolean f;
    public final kotlinx.coroutines.C g;
    public final androidx.compose.ui.unit.b h;
    public final long i;
    public final Object j;
    public final int k;
    public final int l;
    public final int m;
    public final EnumC0320d0 n;
    public final int o;
    public final int p;
    public final /* synthetic */ L q;

    public q(r rVar, int i, boolean z, float f, L l, float f2, boolean z2, kotlinx.coroutines.C c, androidx.compose.ui.unit.b bVar, long j, List list, int i2, int i3, int i4, EnumC0320d0 enumC0320d0, int i5, int i6) {
        this.a = rVar;
        this.b = i;
        this.c = z;
        this.d = f;
        this.e = f2;
        this.f = z2;
        this.g = c;
        this.h = bVar;
        this.i = j;
        this.j = list;
        this.k = i2;
        this.l = i3;
        this.m = i4;
        this.n = enumC0320d0;
        this.o = i5;
        this.p = i6;
        this.q = l;
    }

    public final long a() {
        L l = this.q;
        return R5.a(l.getWidth(), l.b());
    }

    @Override // androidx.compose.ui.layout.L
    public final int b() {
        return this.q.b();
    }

    @Override // androidx.compose.ui.layout.L
    public final Map c() {
        return this.q.c();
    }

    @Override // androidx.compose.ui.layout.L
    public final void d() {
        this.q.d();
    }

    @Override // androidx.compose.ui.layout.L
    public final Function1 e() {
        return this.q.e();
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    public final boolean f(int i, boolean z) {
        r rVar;
        int i2;
        boolean z2;
        if (!this.f) {
            ?? r2 = this.j;
            if (!r2.isEmpty() && (rVar = this.a) != null && (i2 = this.b - i) >= 0 && i2 < rVar.q) {
                r rVar2 = (r) CollectionsKt.L(r2);
                r rVar3 = (r) CollectionsKt.U(r2);
                if (!rVar2.s && !rVar3.s) {
                    int i3 = this.l;
                    int i4 = this.k;
                    if (i >= 0 ? Math.min(i4 - rVar2.o, i3 - rVar3.o) > i : Math.min((rVar2.o + rVar2.q) - i4, (rVar3.o + rVar3.q) - i3) > (-i)) {
                        this.b -= i;
                        int size = r2.size();
                        for (int i5 = 0; i5 < size; i5++) {
                            r rVar4 = (r) r2.get(i5);
                            if (!rVar4.s) {
                                rVar4.o += i;
                                int[] iArr = rVar4.w;
                                int length = iArr.length;
                                int i6 = 0;
                                while (true) {
                                    z2 = rVar4.c;
                                    if (i6 >= length) {
                                        break;
                                    }
                                    if ((z2 && i6 % 2 == 1) || (!z2 && i6 % 2 == 0)) {
                                        iArr[i6] = iArr[i6] + i;
                                    }
                                    i6++;
                                }
                                if (z) {
                                    int size2 = rVar4.b.size();
                                    for (int i7 = 0; i7 < size2; i7++) {
                                        androidx.compose.foundation.lazy.layout.E eA = rVar4.m.a(i7, rVar4.k);
                                        if (eA != null) {
                                            long j = eA.l;
                                            eA.l = P5.b(z2 ? (int) (j >> 32) : ((int) (j >> 32)) + i, z2 ? ((int) (j & 4294967295L)) + i : (int) (j & 4294967295L));
                                        }
                                    }
                                }
                            }
                        }
                        this.d = i;
                        if (!this.c && i > 0) {
                            this.c = true;
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override // androidx.compose.ui.layout.L
    public final int getWidth() {
        return this.q.getWidth();
    }
}
