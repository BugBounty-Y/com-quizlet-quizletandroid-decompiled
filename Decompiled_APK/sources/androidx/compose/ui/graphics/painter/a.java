package androidx.compose.ui.graphics.painter;

import androidx.compose.animation.d0;
import androidx.compose.ui.geometry.e;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.drawscope.d;
import androidx.compose.ui.unit.h;
import androidx.compose.ui.unit.j;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends b {
    public final C0848h f;
    public final long g;
    public int h = 1;
    public final long i;
    public float j;
    public AbstractC0874w k;

    public a(C0848h c0848h, long j) {
        int i;
        int i2;
        this.f = c0848h;
        this.g = j;
        if (((int) 0) < 0 || ((int) 0) < 0 || (i = (int) (j >> 32)) < 0 || (i2 = (int) (4294967295L & j)) < 0 || i > c0848h.a.getWidth() || i2 > c0848h.a.getHeight()) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        this.i = j;
        this.j = 1.0f;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean c(float f) {
        this.j = f;
        return true;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean e(AbstractC0874w abstractC0874w) {
        this.k = abstractC0874w;
        return true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.f, aVar.f) && h.b(0L, 0L) && j.a(this.g, aVar.g) && this.h == aVar.h;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final long h() {
        return R5.f(this.i);
    }

    public final int hashCode() {
        return Integer.hashCode(this.h) + d0.d(d0.d(this.f.hashCode() * 31, 31, 0L), 31, this.g);
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final void i(d dVar) {
        d.P(dVar, this.f, this.g, R5.a(Math.round(e.d(dVar.g())), Math.round(e.b(dVar.g()))), this.j, this.k, this.h, 328);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BitmapPainter(image=");
        sb.append(this.f);
        sb.append(", srcOffset=");
        sb.append((Object) h.e(0L));
        sb.append(", srcSize=");
        sb.append((Object) j.b(this.g));
        sb.append(", filterQuality=");
        int i = this.h;
        sb.append((Object) (i == 0 ? "None" : i == 1 ? "Low" : i == 2 ? "Medium" : i == 3 ? "High" : "Unknown"));
        sb.append(')');
        return sb.toString();
    }
}
