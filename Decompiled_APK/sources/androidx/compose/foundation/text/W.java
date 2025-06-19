package androidx.compose.foundation.text;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.W0;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;

/* loaded from: classes.dex */
public final class W extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ androidx.compose.ui.text.L c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public W(int i, int i2, androidx.compose.ui.text.L l) {
        super(3);
        this.a = i;
        this.b = i2;
        this.c = l;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        ((Number) obj3).intValue();
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        c0814p.X(408240218);
        int i = this.a;
        int i2 = this.b;
        AbstractC0484d0.z(i, i2);
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        if (i == 1 && i2 == Integer.MAX_VALUE) {
            c0814p.p(false);
            return nVar;
        }
        androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
        androidx.compose.ui.text.font.i iVar = (androidx.compose.ui.text.font.i) c0814p.j(AbstractC0955m0.i);
        androidx.compose.ui.unit.k kVar = (androidx.compose.ui.unit.k) c0814p.j(AbstractC0955m0.l);
        androidx.compose.ui.text.L l = this.c;
        boolean zF = c0814p.f(l) | c0814p.f(kVar);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (zF || objI == v) {
            objI = AbstractC3214n5.c(l, kVar);
            c0814p.i0(objI);
        }
        androidx.compose.ui.text.L l2 = (androidx.compose.ui.text.L) objI;
        boolean zF2 = c0814p.f(iVar) | c0814p.f(l2);
        Object objI2 = c0814p.I();
        if (zF2 || objI2 == v) {
            androidx.compose.ui.text.D d = l2.a;
            androidx.compose.ui.text.font.j jVar = d.f;
            androidx.compose.ui.text.font.u uVar = d.c;
            if (uVar == null) {
                uVar = androidx.compose.ui.text.font.u.f;
            }
            androidx.compose.ui.text.font.q qVar = d.d;
            int i3 = qVar != null ? qVar.a : 0;
            androidx.compose.ui.text.font.r rVar = d.e;
            objI2 = ((androidx.compose.ui.text.font.k) iVar).b(jVar, uVar, i3, rVar != null ? rVar.a : 1);
            c0814p.i0(objI2);
        }
        W0 w0 = (W0) objI2;
        boolean zF3 = c0814p.f(w0.getValue()) | c0814p.f(bVar) | c0814p.f(iVar) | c0814p.f(l) | c0814p.f(kVar);
        Object objI3 = c0814p.I();
        if (zF3 || objI3 == v) {
            objI3 = Integer.valueOf((int) (x0.a(l2, bVar, iVar, x0.a, 1) & 4294967295L));
            c0814p.i0(objI3);
        }
        int iIntValue = ((Number) objI3).intValue();
        boolean zF4 = c0814p.f(w0.getValue()) | c0814p.f(bVar) | c0814p.f(iVar) | c0814p.f(l) | c0814p.f(kVar);
        Object objI4 = c0814p.I();
        if (zF4 || objI4 == v) {
            StringBuilder sb = new StringBuilder();
            String str = x0.a;
            sb.append(str);
            sb.append('\n');
            sb.append(str);
            objI4 = Integer.valueOf((int) (x0.a(l2, bVar, iVar, sb.toString(), 2) & 4294967295L));
            c0814p.i0(objI4);
        }
        int iIntValue2 = ((Number) objI4).intValue() - iIntValue;
        Integer numValueOf = i == 1 ? null : Integer.valueOf(((i - 1) * iIntValue2) + iIntValue);
        Integer numValueOf2 = i2 != Integer.MAX_VALUE ? Integer.valueOf(((i2 - 1) * iIntValue2) + iIntValue) : null;
        androidx.compose.ui.q qVarE = androidx.compose.foundation.layout.K0.e(nVar, numValueOf != null ? bVar.O(numValueOf.intValue()) : Float.NaN, numValueOf2 != null ? bVar.O(numValueOf2.intValue()) : Float.NaN);
        c0814p.p(false);
        return qVarE;
    }
}
