package androidx.compose.foundation.layout;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0391i0 implements InterfaceC0387g0 {
    public final InterfaceC0388h a;
    public final InterfaceC0394k b;
    public final float c;
    public final M d;
    public final float e;
    public final int f;
    public final C0381d0 g;
    public final List h;
    public final androidx.compose.runtime.internal.d i;

    public C0391i0(InterfaceC0388h interfaceC0388h, InterfaceC0394k interfaceC0394k, float f, M m, float f2, int i, C0381d0 c0381d0, List list, androidx.compose.runtime.internal.d dVar) {
        this.a = interfaceC0388h;
        this.b = interfaceC0394k;
        this.c = f;
        this.d = m;
        this.e = f2;
        this.f = i;
        this.g = c0381d0;
        this.h = list;
        this.i = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0391i0)) {
            return false;
        }
        C0391i0 c0391i0 = (C0391i0) obj;
        c0391i0.getClass();
        return this.a.equals(c0391i0.a) && this.b.equals(c0391i0.b) && androidx.compose.ui.unit.e.a(this.c, c0391i0.c) && Intrinsics.b(this.d, c0391i0.d) && androidx.compose.ui.unit.e.a(this.e, c0391i0.e) && this.f == c0391i0.f && Intrinsics.b(this.g, c0391i0.g) && Intrinsics.b(this.h, c0391i0.h) && this.i.equals(c0391i0.i);
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final AbstractC0382e f() {
        return this.d;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final InterfaceC0388h g() {
        return this.a;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final InterfaceC0394k h() {
        return this.b;
    }

    public final int hashCode() {
        return this.i.hashCode() + androidx.compose.animation.d0.f((this.g.hashCode() + androidx.compose.animation.d0.b(SubsamplingScaleImageView.TILE_SIZE_AUTO, androidx.compose.animation.d0.b(SubsamplingScaleImageView.TILE_SIZE_AUTO, androidx.compose.animation.d0.b(this.f, android.support.v4.media.session.a.b((this.d.hashCode() + android.support.v4.media.session.a.b((this.b.hashCode() + ((this.a.hashCode() + (Boolean.hashCode(true) * 31)) * 31)) * 31, this.c, 31)) * 31, this.e, 31), 31), 31), 31)) * 31, 31, this.h);
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0387g0
    public final boolean i() {
        return true;
    }

    public final String toString() {
        return "FlowMeasureLazyPolicy(isHorizontal=true, horizontalArrangement=" + this.a + ", verticalArrangement=" + this.b + ", mainAxisSpacing=" + ((Object) androidx.compose.ui.unit.e.b(this.c)) + ", crossAxisAlignment=" + this.d + ", crossAxisArrangementSpacing=" + ((Object) androidx.compose.ui.unit.e.b(this.e)) + ", itemCount=" + this.f + ", maxLines=2147483647, maxItemsInMainAxis=2147483647, overflow=" + this.g + ", overflowComposables=" + this.h + ", getComposable=" + this.i + ')';
    }
}
