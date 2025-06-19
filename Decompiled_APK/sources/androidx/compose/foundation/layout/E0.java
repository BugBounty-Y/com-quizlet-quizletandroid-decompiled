package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class E0 {
    public static final G0 a = new G0(AbstractC0398m.a, androidx.compose.ui.b.j);

    public static final long a(boolean z, int i, int i2, int i3) {
        if (!z) {
            return L5.a(i, i2, 0, i3);
        }
        int iMin = Math.min(i, 262142);
        int iMin2 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iMin3 = i2 == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.min(i2, 262142);
        int iG = L5.g(iMin3 == Integer.MAX_VALUE ? iMin : iMin3);
        if (i3 != Integer.MAX_VALUE) {
            iMin2 = Math.min(iG, i3);
        }
        return L5.a(iMin, iMin3, Math.min(iG, 0), iMin2);
    }

    public static final G0 b(InterfaceC0388h interfaceC0388h, androidx.compose.ui.h hVar, InterfaceC0806l interfaceC0806l, int i) {
        if (Intrinsics.b(interfaceC0388h, AbstractC0398m.a) && Intrinsics.b(hVar, androidx.compose.ui.b.j)) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            c0814p.X(-849081669);
            c0814p.p(false);
            return a;
        }
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.X(-849030798);
        boolean z = true;
        boolean z2 = (((i & 14) ^ 6) > 4 && c0814p2.f(interfaceC0388h)) || (i & 6) == 4;
        if ((((i & ContentType.LONG_FORM_ON_DEMAND) ^ 48) <= 32 || !c0814p2.f(hVar)) && (i & 48) != 32) {
            z = false;
        }
        boolean z3 = z2 | z;
        Object objI = c0814p2.I();
        if (z3 || objI == C0804k.a) {
            objI = new G0(interfaceC0388h, hVar);
            c0814p2.i0(objI);
        }
        G0 g0 = (G0) objI;
        c0814p2.p(false);
        return g0;
    }
}
