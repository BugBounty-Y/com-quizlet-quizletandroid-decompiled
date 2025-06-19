package androidx.compose.foundation.lazy;

import androidx.compose.foundation.lazy.layout.U;
import androidx.compose.foundation.lazy.layout.V;
import androidx.compose.foundation.lazy.layout.W;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import java.util.List;

/* loaded from: classes.dex */
public final class m implements W {
    public final h a;
    public final U b;
    public final long c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ U e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ androidx.compose.ui.c h;
    public final /* synthetic */ androidx.compose.ui.h i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ long l;
    public final /* synthetic */ A m;

    public m(long j, boolean z, h hVar, U u, int i, int i2, androidx.compose.ui.c cVar, androidx.compose.ui.h hVar2, int i3, int i4, long j2, A a) {
        this.d = z;
        this.e = u;
        this.f = i;
        this.g = i2;
        this.h = cVar;
        this.i = hVar2;
        this.j = i3;
        this.k = i4;
        this.l = j2;
        this.m = a;
        this.a = hVar;
        this.b = u;
        this.c = L5.b(z ? androidx.compose.ui.unit.a.h(j) : Integer.MAX_VALUE, z ? SubsamplingScaleImageView.TILE_SIZE_AUTO : androidx.compose.ui.unit.a.g(j), 5);
    }

    @Override // androidx.compose.foundation.lazy.layout.W
    public final V a(long j, int i, int i2, int i3) {
        return b(i, j);
    }

    public final r b(int i, long j) {
        h hVar = this.a;
        Object objB = hVar.b(i);
        Object objI = hVar.b.i(i);
        List listB = this.b.b(i, j);
        int i2 = i == this.f + (-1) ? 0 : this.g;
        return new r(i, listB, this.d, this.h, this.i, this.e.b.getLayoutDirection(), this.j, this.k, i2, this.l, objB, objI, this.m.n, j);
    }
}
