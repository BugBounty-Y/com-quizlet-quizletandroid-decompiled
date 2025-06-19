package androidx.camera.view;

import android.graphics.Rect;
import android.util.Rational;
import androidx.camera.camera2.internal.T;
import androidx.camera.camera2.internal.p0;
import androidx.camera.core.W;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.j0;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class e implements W {
    public final /* synthetic */ PreviewView a;

    public e(PreviewView previewView) {
        this.a = previewView;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.camera.core.W
    public final void a(j0 j0Var) {
        q qVar;
        if (!S.e()) {
            androidx.core.content.c.d(this.a.getContext()).execute(new androidx.activity.r(21, this, j0Var));
            return;
        }
        AbstractC3053s1.f(3, "PreviewView");
        InterfaceC0185y interfaceC0185y = j0Var.d;
        this.a.i = interfaceC0185y.n();
        k kVar = this.a.h;
        Rect rectB = interfaceC0185y.g().b();
        kVar.getClass();
        new Rational(rectB.width(), rectB.height());
        synchronized (kVar) {
            kVar.b = rectB;
        }
        j0Var.b(androidx.core.content.c.d(this.a.getContext()), new T(this, interfaceC0185y, j0Var, 3));
        PreviewView previewView = this.a;
        j jVar = previewView.b;
        g gVar = previewView.a;
        if (!(jVar instanceof q) || PreviewView.b(j0Var, gVar)) {
            PreviewView previewView2 = this.a;
            if (PreviewView.b(j0Var, previewView2.a)) {
                PreviewView previewView3 = this.a;
                s sVar = new s(previewView3, previewView3.d);
                sVar.i = false;
                sVar.k = new AtomicReference();
                qVar = sVar;
            } else {
                PreviewView previewView4 = this.a;
                qVar = new q(previewView4, previewView4.d);
            }
            previewView2.b = qVar;
        }
        InterfaceC0183w interfaceC0183wN = interfaceC0185y.n();
        PreviewView previewView5 = this.a;
        Y y = previewView5.f;
        j jVar2 = previewView5.b;
        p0 p0Var = new p0();
        p0Var.b = false;
        p0Var.c = interfaceC0183wN;
        p0Var.a = y;
        p0Var.e = jVar2;
        synchronized (p0Var) {
            p0Var.d = (i) y.d();
        }
        this.a.g.set(p0Var);
        interfaceC0185y.f().c(androidx.core.content.c.d(this.a.getContext()), p0Var);
        this.a.b.h(j0Var, new T(this, p0Var, interfaceC0185y, 4));
        PreviewView previewView6 = this.a;
        if (previewView6.indexOfChild(previewView6.c) == -1) {
            PreviewView previewView7 = this.a;
            previewView7.addView(previewView7.c);
        }
    }
}
