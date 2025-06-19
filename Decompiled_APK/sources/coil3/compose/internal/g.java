package coil3.compose.internal;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.layout.InterfaceC0889j;
import coil3.compose.p;
import coil3.size.i;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class g {
    public static final long a = L5.b(0, 0, 5);
    public static final /* synthetic */ int b = 0;

    public static final i a(InterfaceC0889j interfaceC0889j, InterfaceC0806l interfaceC0806l) {
        Object obj;
        boolean zB = Intrinsics.b(interfaceC0889j, C0888i.f);
        C0814p c0814p = (C0814p) interfaceC0806l;
        boolean zG = c0814p.g(zB);
        Object objI = c0814p.I();
        if (zG || objI == C0804k.a) {
            if (zB) {
                obj = i.a;
            } else {
                p pVar = new p();
                pVar.b = a;
                obj = pVar;
            }
            objI = obj;
            c0814p.i0(objI);
        }
        return (i) objI;
    }

    public static void b(String str) {
        throw new IllegalArgumentException(android.support.v4.media.session.a.m("Unsupported type: ", str, ". ", android.support.v4.media.session.a.B("If you wish to display this ", str, ", use androidx.compose.foundation.Image.")));
    }
}
