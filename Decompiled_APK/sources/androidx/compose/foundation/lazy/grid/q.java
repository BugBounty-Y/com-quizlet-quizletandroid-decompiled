package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.layout.L;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class q implements L {
    public final s a;
    public int b;
    public boolean c;
    public float d;
    public final boolean e;
    public final kotlin.jvm.internal.r f;
    public final Object g;
    public final int h;
    public final int i;
    public final int j;
    public final EnumC0320d0 k;
    public final int l;
    public final int m;
    public final /* synthetic */ L n;

    /* JADX WARN: Multi-variable type inference failed */
    public q(s sVar, int i, boolean z, float f, L l, boolean z2, int i2, Function1 function1, List list, int i3, int i4, int i5, EnumC0320d0 enumC0320d0, int i6, int i7) {
        this.a = sVar;
        this.b = i;
        this.c = z;
        this.d = f;
        this.e = z2;
        this.f = (kotlin.jvm.internal.r) function1;
        this.g = list;
        this.h = i3;
        this.i = i4;
        this.j = i5;
        this.k = enumC0320d0;
        this.l = i6;
        this.m = i7;
        this.n = l;
    }

    @Override // androidx.compose.ui.layout.L
    public final int b() {
        return this.n.b();
    }

    @Override // androidx.compose.ui.layout.L
    public final Map c() {
        return this.n.c();
    }

    @Override // androidx.compose.ui.layout.L
    public final void d() {
        this.n.d();
    }

    @Override // androidx.compose.ui.layout.L
    public final Function1 e() {
        return this.n.e();
    }

    @Override // androidx.compose.ui.layout.L
    public final int getWidth() {
        return this.n.getWidth();
    }
}
