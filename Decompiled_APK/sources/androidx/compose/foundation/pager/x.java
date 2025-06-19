package androidx.compose.foundation.pager;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.layout.L;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class x implements L {
    public final Object a;
    public final int b;
    public final int c;
    public final int d;
    public final EnumC0320d0 e;
    public final int f;
    public final int g;
    public final int h;
    public final C0472k i;
    public final C0472k j;
    public float k;
    public int l;
    public boolean m;
    public final androidx.compose.foundation.gestures.snapping.n n;
    public final boolean o;
    public final List p;
    public final List q;
    public final /* synthetic */ L r;

    public x(List list, int i, int i2, int i3, int i4, int i5, int i6, C0472k c0472k, C0472k c0472k2, float f, int i7, boolean z, androidx.compose.foundation.gestures.snapping.n nVar, L l, boolean z2, List list2, List list3) {
        EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
        this.a = list;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = enumC0320d0;
        this.f = i4;
        this.g = i5;
        this.h = i6;
        this.i = c0472k;
        this.j = c0472k2;
        this.k = f;
        this.l = i7;
        this.m = z;
        this.n = nVar;
        this.o = z2;
        this.p = list2;
        this.q = list3;
        this.r = l;
    }

    public final long a() {
        L l = this.r;
        return R5.a(l.getWidth(), l.b());
    }

    @Override // androidx.compose.ui.layout.L
    public final int b() {
        return this.r.b();
    }

    @Override // androidx.compose.ui.layout.L
    public final Map c() {
        return this.r.c();
    }

    @Override // androidx.compose.ui.layout.L
    public final void d() {
        this.r.d();
    }

    @Override // androidx.compose.ui.layout.L
    public final Function1 e() {
        return this.r.e();
    }

    @Override // androidx.compose.ui.layout.L
    public final int getWidth() {
        return this.r.getWidth();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public x(kotlin.collections.K k, int i, int i2, int i3, int i4, int i5, int i6, androidx.compose.foundation.gestures.snapping.n nVar, L l) {
        kotlin.collections.K k2 = kotlin.collections.K.a;
        this(k, i, i2, i3, i4, i5, i6, null, null, DefinitionKt.NO_Float_VALUE, 0, false, nVar, l, false, k2, k2);
    }
}
