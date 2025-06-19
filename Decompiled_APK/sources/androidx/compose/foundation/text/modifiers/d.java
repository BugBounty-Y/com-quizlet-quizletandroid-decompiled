package androidx.compose.foundation.text.modifiers;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.G;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.L;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3209n0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public C0995g a;
    public L b;
    public androidx.compose.ui.text.font.i c;
    public int d;
    public boolean e;
    public int f;
    public int g;
    public List h;
    public b i;
    public androidx.compose.ui.unit.b k;
    public com.quizlet.remote.model.notes.e l;
    public androidx.compose.ui.unit.k m;
    public H n;
    public long j = a.a;
    public int o = -1;
    public int p = -1;

    public d(C0995g c0995g, L l, androidx.compose.ui.text.font.i iVar, int i, boolean z, int i2, int i3, List list) {
        this.a = c0995g;
        this.b = l;
        this.c = iVar;
        this.d = i;
        this.e = z;
        this.f = i2;
        this.g = i3;
        this.h = list;
    }

    public final int a(int i, androidx.compose.ui.unit.k kVar) {
        int i2 = this.o;
        int i3 = this.p;
        if (i == i2 && i2 != -1) {
            return i3;
        }
        int iQ = AbstractC0484d0.q(b(L5.a(0, i, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO), kVar).e);
        this.o = i;
        this.p = iQ;
        return iQ;
    }

    public final androidx.compose.ui.text.o b(long j, androidx.compose.ui.unit.k kVar) {
        com.quizlet.remote.model.notes.e eVarD = d(kVar);
        long jE = AbstractC3209n0.e(j, this.e, this.d, eVarD.d());
        boolean z = this.e;
        int i = this.d;
        int i2 = this.f;
        if ((!z && i == 2) || i2 < 1) {
            i2 = 1;
        }
        return new androidx.compose.ui.text.o(eVarD, jE, i2, i == 2);
    }

    public final void c(androidx.compose.ui.unit.b bVar) {
        long jA;
        androidx.compose.ui.unit.b bVar2 = this.k;
        if (bVar != null) {
            int i = a.b;
            jA = a.a(bVar.a(), bVar.Z());
        } else {
            jA = a.a;
        }
        if (bVar2 == null) {
            this.k = bVar;
            this.j = jA;
        } else if (bVar == null || this.j != jA) {
            this.k = bVar;
            this.j = jA;
            this.l = null;
            this.n = null;
            this.p = -1;
            this.o = -1;
        }
    }

    public final com.quizlet.remote.model.notes.e d(androidx.compose.ui.unit.k kVar) {
        com.quizlet.remote.model.notes.e eVar = this.l;
        if (eVar == null || kVar != this.m || eVar.a()) {
            this.m = kVar;
            C0995g c0995g = this.a;
            L lC = AbstractC3214n5.c(this.b, kVar);
            androidx.compose.ui.unit.b bVar = this.k;
            Intrinsics.d(bVar);
            androidx.compose.ui.text.font.i iVar = this.c;
            List list = this.h;
            if (list == null) {
                list = K.a;
            }
            eVar = new com.quizlet.remote.model.notes.e(c0995g, lC, list, bVar, iVar);
        }
        this.l = eVar;
        return eVar;
    }

    public final H e(androidx.compose.ui.unit.k kVar, long j, androidx.compose.ui.text.o oVar) {
        float fMin = Math.min(oVar.a.d(), oVar.d);
        C0995g c0995g = this.a;
        L l = this.b;
        List list = this.h;
        if (list == null) {
            list = K.a;
        }
        int i = this.f;
        boolean z = this.e;
        int i2 = this.d;
        androidx.compose.ui.unit.b bVar = this.k;
        Intrinsics.d(bVar);
        return new H(new G(c0995g, l, list, i, z, i2, bVar, kVar, this.c, j), oVar, L5.i(j, R5.a(AbstractC0484d0.q(fMin), AbstractC0484d0.q(oVar.e))));
    }
}
