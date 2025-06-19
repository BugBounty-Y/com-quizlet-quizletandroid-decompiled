package androidx.camera.core.imagecapture;

import androidx.activity.RunnableC0041m;
import androidx.camera.core.AbstractC0199w;
import androidx.camera.core.ImageCaptureException;
import androidx.camera.core.InterfaceC0198v;
import androidx.camera.core.Q;
import androidx.camera.core.a0;
import androidx.work.impl.model.v;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class d implements InterfaceC0198v {
    public C1721Kc b;
    public final ArrayList c;
    public final ArrayDeque a = new ArrayDeque();
    public boolean d = false;

    public d(Q q) {
        S.d();
        this.c = new ArrayList();
    }

    @Override // androidx.camera.core.InterfaceC0198v
    public final void a(AbstractC0199w abstractC0199w) {
        T.e().execute(new RunnableC0041m(this, 12));
    }

    public final void b() {
        S.d();
        new ImageCaptureException("Camera is closed.", null);
        ArrayDeque arrayDeque = this.a;
        Iterator it2 = arrayDeque.iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
        arrayDeque.clear();
        Iterator it3 = new ArrayList(this.c).iterator();
        if (it3.hasNext()) {
            android.support.v4.media.session.a.A(it3.next());
            throw null;
        }
    }

    public final void c() {
        int iC;
        S.d();
        if (this.d) {
            return;
        }
        C1721Kc c1721Kc = this.b;
        c1721Kc.getClass();
        S.d();
        v vVar = (v) c1721Kc.c;
        vVar.getClass();
        S.d();
        AbstractC3242q6.h("The ImageReader is not initialized.", ((a0) vVar.b) != null);
        a0 a0Var = (a0) vVar.b;
        synchronized (a0Var.c) {
            iC = ((androidx.camera.core.impl.S) a0Var.d).C() - a0Var.a;
        }
        if (iC != 0 && this.a.poll() != null) {
            throw new ClassCastException();
        }
    }
}
