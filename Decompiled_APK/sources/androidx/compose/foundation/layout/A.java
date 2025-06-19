package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class A {
    public static final B a = new B(AbstractC0398m.c, androidx.compose.ui.b.m);

    public static final B a(InterfaceC0394k interfaceC0394k, androidx.compose.ui.g gVar, InterfaceC0806l interfaceC0806l, int i) {
        if (Intrinsics.b(interfaceC0394k, AbstractC0398m.c) && gVar.equals(androidx.compose.ui.b.m)) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            c0814p.X(345962472);
            c0814p.p(false);
            return a;
        }
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.X(346016319);
        boolean z = true;
        boolean z2 = (((i & 14) ^ 6) > 4 && c0814p2.f(interfaceC0394k)) || (i & 6) == 4;
        if ((((i & ContentType.LONG_FORM_ON_DEMAND) ^ 48) <= 32 || !c0814p2.f(gVar)) && (i & 48) != 32) {
            z = false;
        }
        boolean z3 = z2 | z;
        Object objI = c0814p2.I();
        if (z3 || objI == C0804k.a) {
            objI = new B(interfaceC0394k, gVar);
            c0814p2.i0(objI);
        }
        B b = (B) objI;
        c0814p2.p(false);
        return b;
    }

    public static final long b(boolean z, int i, int i2, int i3) {
        if (!z) {
            return L5.a(0, i3, i, i2);
        }
        int iMin = Math.min(i, 262142);
        int iMin2 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iMin3 = i2 == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.min(i2, 262142);
        int iG = L5.g(iMin3 == Integer.MAX_VALUE ? iMin : iMin3);
        if (i3 != Integer.MAX_VALUE) {
            iMin2 = Math.min(iG, i3);
        }
        return L5.a(Math.min(iG, 0), iMin2, iMin, iMin3);
    }
}
