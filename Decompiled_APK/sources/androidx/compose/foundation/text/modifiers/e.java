package androidx.compose.foundation.text.modifiers;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.ui.text.C0982b;
import androidx.compose.ui.text.L;
import androidx.compose.ui.text.s;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3209n0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public String a;
    public L b;
    public androidx.compose.ui.text.font.i c;
    public int d;
    public boolean e;
    public int f;
    public int g;
    public androidx.compose.ui.unit.b i;
    public C0982b j;
    public boolean k;
    public b m;
    public s n;
    public androidx.compose.ui.unit.k o;
    public long h = a.a;
    public long l = R5.a(0, 0);
    public long p = L5.m(0, 0, 0, 0);
    public int q = -1;
    public int r = -1;

    public e(String str, L l, androidx.compose.ui.text.font.i iVar, int i, boolean z, int i2, int i3) {
        this.a = str;
        this.b = l;
        this.c = iVar;
        this.d = i;
        this.e = z;
        this.f = i2;
        this.g = i3;
    }

    public final int a(int i, androidx.compose.ui.unit.k kVar) {
        int i2 = this.q;
        int i3 = this.r;
        if (i == i2 && i2 != -1) {
            return i3;
        }
        int iQ = AbstractC0484d0.q(b(L5.a(0, i, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO), kVar).b());
        this.q = i;
        this.r = iQ;
        return iQ;
    }

    public final C0982b b(long j, androidx.compose.ui.unit.k kVar) {
        s sVarD = d(kVar);
        long jE = AbstractC3209n0.e(j, this.e, this.d, sVarD.d());
        boolean z = this.e;
        int i = this.d;
        int i2 = this.f;
        return new C0982b((androidx.compose.ui.text.platform.c) sVarD, ((z || i != 2) && i2 >= 1) ? i2 : 1, i == 2, jE);
    }

    public final void c(androidx.compose.ui.unit.b bVar) {
        long jA;
        androidx.compose.ui.unit.b bVar2 = this.i;
        if (bVar != null) {
            int i = a.b;
            jA = a.a(bVar.a(), bVar.Z());
        } else {
            jA = a.a;
        }
        if (bVar2 == null) {
            this.i = bVar;
            this.h = jA;
            return;
        }
        if (bVar == null || this.h != jA) {
            this.i = bVar;
            this.h = jA;
            this.j = null;
            this.n = null;
            this.o = null;
            this.q = -1;
            this.r = -1;
            this.p = L5.m(0, 0, 0, 0);
            this.l = R5.a(0, 0);
            this.k = false;
        }
    }

    public final s d(androidx.compose.ui.unit.k kVar) {
        s cVar = this.n;
        if (cVar == null || kVar != this.o || cVar.a()) {
            this.o = kVar;
            String str = this.a;
            L lC = AbstractC3214n5.c(this.b, kVar);
            androidx.compose.ui.unit.b bVar = this.i;
            Intrinsics.d(bVar);
            androidx.compose.ui.text.font.i iVar = this.c;
            K k = K.a;
            cVar = new androidx.compose.ui.text.platform.c(str, lC, k, k, iVar, bVar);
        }
        this.n = cVar;
        return cVar;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ParagraphLayoutCache(paragraph=");
        sb.append(this.j != null ? "<paragraph>" : "null");
        sb.append(", lastDensity=");
        long j = this.h;
        int i = a.b;
        sb.append((Object) ("InlineDensity(density=" + Float.intBitsToFloat((int) (j >> 32)) + ", fontScale=" + Float.intBitsToFloat((int) (j & 4294967295L)) + ')'));
        sb.append(')');
        return sb.toString();
    }
}
