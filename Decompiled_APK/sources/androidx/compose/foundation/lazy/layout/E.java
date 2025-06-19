package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.M0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class E {
    public static final long s = P5.b(SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO);
    public static final /* synthetic */ int t = 0;
    public final kotlinx.coroutines.C a;
    public final androidx.compose.ui.graphics.E b;
    public final androidx.compose.animation.core.K c;
    public androidx.compose.animation.core.D d;
    public C0253l0 e;
    public androidx.compose.animation.core.D f;
    public boolean g;
    public final InterfaceC0773a0 h;
    public final InterfaceC0773a0 i;
    public final InterfaceC0773a0 j;
    public final InterfaceC0773a0 k;
    public long l;
    public long m;
    public androidx.compose.ui.graphics.layer.b n;
    public final C0238e o;
    public final C0238e p;
    public final InterfaceC0773a0 q;
    public long r;

    public E(kotlinx.coroutines.C c, androidx.compose.ui.graphics.E e, androidx.compose.animation.core.K k) {
        this.a = c;
        this.b = e;
        this.c = k;
        Boolean bool = Boolean.FALSE;
        this.h = C0776c.z(bool);
        this.i = C0776c.z(bool);
        this.j = C0776c.z(bool);
        this.k = C0776c.z(bool);
        long j = s;
        this.l = j;
        this.m = 0L;
        this.n = e != null ? e.b() : null;
        this.o = new C0238e(new androidx.compose.ui.unit.h(0L), M0.g, null, 12);
        this.p = new C0238e(Float.valueOf(1.0f), M0.a, null, 12);
        this.q = C0776c.z(new androidx.compose.ui.unit.h(0L));
        this.r = j;
    }

    public final void a() {
        androidx.compose.ui.graphics.layer.b bVar = this.n;
        androidx.compose.animation.core.D d = this.d;
        boolean zBooleanValue = ((Boolean) ((L0) this.i).getValue()).booleanValue();
        kotlinx.coroutines.C c = this.a;
        if (zBooleanValue || d == null || bVar == null) {
            if (b()) {
                if (bVar != null) {
                    bVar.f(1.0f);
                }
                kotlinx.coroutines.E.A(c, null, null, new C0449v(this, null), 3);
                return;
            }
            return;
        }
        d(true);
        boolean zB = b();
        boolean z = !zB;
        if (!zB) {
            bVar.f(DefinitionKt.NO_Float_VALUE);
        }
        kotlinx.coroutines.E.A(c, null, null, new C0451x(z, this, d, bVar, null), 3);
    }

    public final boolean b() {
        return ((Boolean) ((L0) this.j).getValue()).booleanValue();
    }

    public final void c() {
        androidx.compose.ui.graphics.E e;
        boolean zBooleanValue = ((Boolean) ((L0) this.h).getValue()).booleanValue();
        kotlinx.coroutines.C c = this.a;
        if (zBooleanValue) {
            f(false);
            kotlinx.coroutines.E.A(c, null, null, new B(this, null), 3);
        }
        if (((Boolean) ((L0) this.i).getValue()).booleanValue()) {
            d(false);
            kotlinx.coroutines.E.A(c, null, null, new C(this, null), 3);
        }
        if (b()) {
            e(false);
            kotlinx.coroutines.E.A(c, null, null, new D(this, null), 3);
        }
        this.g = false;
        g(0L);
        this.l = s;
        androidx.compose.ui.graphics.layer.b bVar = this.n;
        if (bVar != null && (e = this.b) != null) {
            e.a(bVar);
        }
        this.n = null;
        this.d = null;
        this.f = null;
        this.e = null;
    }

    public final void d(boolean z) {
        ((L0) this.i).setValue(Boolean.valueOf(z));
    }

    public final void e(boolean z) {
        ((L0) this.j).setValue(Boolean.valueOf(z));
    }

    public final void f(boolean z) {
        ((L0) this.h).setValue(Boolean.valueOf(z));
    }

    public final void g(long j) {
        ((L0) this.q).setValue(new androidx.compose.ui.unit.h(j));
    }
}
