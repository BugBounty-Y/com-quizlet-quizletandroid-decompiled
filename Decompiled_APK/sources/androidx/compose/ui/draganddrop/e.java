package androidx.compose.ui.draganddrop;

import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.q0;
import androidx.compose.ui.p;

/* loaded from: classes.dex */
public final class e extends p implements q0, InterfaceC0917m {
    public e n;

    @Override // androidx.compose.ui.p
    public final void F0() {
        this.n = null;
    }

    public final boolean M0(com.google.android.gms.internal.instantapps.a aVar) {
        e eVar = this.n;
        if (eVar == null) {
            return false;
        }
        return eVar.M0(aVar);
    }

    public final void N0(com.google.android.gms.internal.instantapps.a aVar) {
        e eVar = this.n;
        if (eVar != null) {
            eVar.N0(aVar);
        }
    }

    public final void O0(com.google.android.gms.internal.instantapps.a aVar) {
        e eVar = this.n;
        if (eVar != null) {
            eVar.O0(aVar);
        }
        this.n = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void P0(com.google.android.gms.internal.instantapps.a r5) {
        /*
            r4 = this;
            androidx.compose.ui.draganddrop.e r0 = r4.n
            if (r0 == 0) goto L1d
            java.lang.Object r1 = r5.b
            android.view.DragEvent r1 = (android.view.DragEvent) r1
            float r2 = r1.getX()
            float r1 = r1.getY()
            long r1 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(r2, r1)
            boolean r1 = com.google.android.gms.internal.mlkit_vision_barcode.N4.f(r0, r1)
            r2 = 1
            if (r1 != r2) goto L1d
            r1 = r0
            goto L3a
        L1d:
            androidx.compose.ui.p r1 = r4.a
            boolean r1 = r1.m
            if (r1 != 0) goto L25
            r1 = 0
            goto L38
        L25:
            kotlin.jvm.internal.J r1 = new kotlin.jvm.internal.J
            r1.<init>()
            androidx.activity.compose.g r2 = new androidx.activity.compose.g
            r3 = 22
            r2.<init>(r1, r4, r5, r3)
            androidx.compose.ui.node.AbstractC0910f.z(r4, r2)
            java.lang.Object r1 = r1.a
            androidx.compose.ui.node.q0 r1 = (androidx.compose.ui.node.q0) r1
        L38:
            androidx.compose.ui.draganddrop.e r1 = (androidx.compose.ui.draganddrop.e) r1
        L3a:
            if (r1 == 0) goto L45
            if (r0 != 0) goto L45
            r1.N0(r5)
            r1.P0(r5)
            goto L66
        L45:
            if (r1 != 0) goto L4d
            if (r0 == 0) goto L4d
            r0.O0(r5)
            goto L66
        L4d:
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r1, r0)
            if (r2 != 0) goto L61
            if (r1 == 0) goto L5b
            r1.N0(r5)
            r1.P0(r5)
        L5b:
            if (r0 == 0) goto L66
            r0.O0(r5)
            goto L66
        L61:
            if (r1 == 0) goto L66
            r1.P0(r5)
        L66:
            r4.n = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.draganddrop.e.P0(com.google.android.gms.internal.instantapps.a):void");
    }

    public final void Q0(com.google.android.gms.internal.instantapps.a aVar) {
        e eVar = this.n;
        if (eVar != null) {
            eVar.Q0(aVar);
        }
    }

    @Override // androidx.compose.ui.node.q0
    public final Object m() {
        return c.a;
    }
}
