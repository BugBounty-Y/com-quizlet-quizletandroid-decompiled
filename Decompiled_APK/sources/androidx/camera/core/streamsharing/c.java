package androidx.camera.core.streamsharing;

import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.o0;
import androidx.camera.core.impl.q0;
import androidx.camera.core.l0;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import java.util.Iterator;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements o0 {
    public final /* synthetic */ d a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ A0 d;
    public final /* synthetic */ C0168g e;
    public final /* synthetic */ C0168g f;

    public /* synthetic */ c(d dVar, String str, String str2, A0 a0, C0168g c0168g, C0168g c0168g2) {
        this.a = dVar;
        this.b = str;
        this.c = str2;
        this.d = a0;
        this.e = c0168g;
        this.f = c0168g2;
    }

    @Override // androidx.camera.core.impl.o0
    public final void a(q0 q0Var) {
        d dVar = this.a;
        if (dVar.b() == null) {
            return;
        }
        dVar.B();
        dVar.A(dVar.C(this.b, this.c, this.d, this.e, this.f));
        dVar.n();
        g gVar = dVar.p;
        gVar.getClass();
        S.d();
        Iterator it2 = gVar.a.iterator();
        while (it2.hasNext()) {
            gVar.d((l0) it2.next());
        }
    }
}
