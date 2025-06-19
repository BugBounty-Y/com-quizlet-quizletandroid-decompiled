package androidx.compose.ui.text;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public final class J {
    public final androidx.compose.ui.text.font.i a;
    public final androidx.compose.ui.unit.b b;
    public final androidx.compose.ui.unit.k c;
    public final com.google.android.gms.auth.api.signin.internal.h d = new com.google.android.gms.auth.api.signin.internal.h(11);

    public J(androidx.compose.ui.text.font.i iVar, androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        this.a = iVar;
        this.b = bVar;
        this.c = kVar;
    }

    public static H a(J j, String str, L l, long j2, int i) {
        L l2 = (i & 2) != 0 ? L.d : l;
        long jB = (i & 32) != 0 ? L5.b(0, 0, 15) : j2;
        androidx.compose.ui.unit.k kVar = j.c;
        androidx.compose.ui.unit.b bVar = j.b;
        androidx.compose.ui.text.font.i iVar = j.a;
        j.getClass();
        H h = null;
        C0995g c0995g = new C0995g(6, str, null);
        kotlin.collections.K k = kotlin.collections.K.a;
        G g = new G(c0995g, l2, k, SubsamplingScaleImageView.TILE_SIZE_AUTO, true, 1, bVar, kVar, iVar, jB);
        com.google.android.gms.auth.api.signin.internal.h hVar = j.d;
        if (hVar != null) {
            H h2 = (H) ((androidx.compose.ui.text.caches.b) hVar.b).b(new C1009j(g));
            if (h2 != null && !h2.b.a.a()) {
                h = h2;
            }
        }
        if (h != null) {
            return new H(g, h.b, L5.i(jB, R5.a((int) Math.ceil(r0.d), (int) Math.ceil(r0.e))));
        }
        com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(c0995g, AbstractC3214n5.c(l2, kVar), k, bVar, iVar);
        int iJ = androidx.compose.ui.unit.a.j(jB);
        boolean zD = androidx.compose.ui.unit.a.d(jB);
        int iMin = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iH = zD ? androidx.compose.ui.unit.a.h(jB) : Integer.MAX_VALUE;
        if (iJ != iH) {
            iH = kotlin.ranges.l.c((int) Math.ceil(eVar.d()), iJ, iH);
        }
        int iG = androidx.compose.ui.unit.a.g(jB);
        int iMin2 = Math.min(0, 262142);
        int iMin3 = iH == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.min(iH, 262142);
        int iG2 = L5.g(iMin3 == Integer.MAX_VALUE ? iMin2 : iMin3);
        if (iG != Integer.MAX_VALUE) {
            iMin = Math.min(iG2, iG);
        }
        H h3 = new H(g, new o(eVar, L5.a(iMin2, iMin3, Math.min(iG2, 0), iMin), SubsamplingScaleImageView.TILE_SIZE_AUTO, false), L5.i(jB, R5.a((int) Math.ceil(r3.d), (int) Math.ceil(r3.e))));
        if (hVar != null) {
        }
        return h3;
    }
}
