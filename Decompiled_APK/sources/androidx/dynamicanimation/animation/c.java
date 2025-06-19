package androidx.dynamicanimation.animation;

import android.os.Looper;
import android.util.AndroidRuntimeException;
import android.view.Choreographer;
import androidx.compose.foundation.layout.C0386g;
import androidx.transition.C1418v;
import androidx.transition.F;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class c {
    public final com.google.firebase.platforminfo.c d;
    public float a = DefinitionKt.NO_Float_VALUE;
    public float b = Float.MAX_VALUE;
    public boolean c = false;
    public boolean e = false;
    public float f = Float.MAX_VALUE;
    public float g = -3.4028235E38f;
    public long h = 0;
    public final ArrayList j = new ArrayList();
    public final ArrayList k = new ArrayList();
    public float i = 1.0f;
    public d l = null;
    public float m = Float.MAX_VALUE;

    public c(C0386g c0386g) {
        this.d = new com.google.firebase.platforminfo.c(c0386g);
    }

    public final void a(float f) {
        if (this.e) {
            this.m = f;
            return;
        }
        if (this.l == null) {
            this.l = new d(f);
        }
        d dVar = this.l;
        double d = f;
        dVar.i = d;
        double d2 = (float) d;
        if (d2 > this.f) {
            throw new UnsupportedOperationException("Final position of the spring cannot be greater than the max value.");
        }
        if (d2 < this.g) {
            throw new UnsupportedOperationException("Final position of the spring cannot be less than the min value.");
        }
        double dAbs = Math.abs(this.i * 0.75f);
        dVar.d = dAbs;
        dVar.e = dAbs * 62.5d;
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new AndroidRuntimeException("Animations may only be started on the main thread");
        }
        boolean z = this.e;
        if (z || z) {
            return;
        }
        this.e = true;
        if (!this.c) {
            this.b = ((C0386g) this.d.a).b;
        }
        float f2 = this.b;
        if (f2 > this.f || f2 < this.g) {
            throw new IllegalArgumentException("Starting value need to be in between min value and max value");
        }
        ThreadLocal threadLocal = b.f;
        if (threadLocal.get() == null) {
            threadLocal.set(new b());
        }
        b bVar = (b) threadLocal.get();
        ArrayList arrayList = bVar.b;
        if (arrayList.size() == 0) {
            if (bVar.d == null) {
                bVar.d = new com.quizlet.data.repository.folderset.c(bVar.c);
            }
            com.quizlet.data.repository.folderset.c cVar = bVar.d;
            ((Choreographer) cVar.c).postFrameCallback((a) cVar.d);
        }
        if (arrayList.contains(this)) {
            return;
        }
        arrayList.add(this);
    }

    public final void b(float f) {
        ArrayList arrayList;
        ((C0386g) this.d.a).b = f;
        int i = 0;
        while (true) {
            arrayList = this.k;
            if (i >= arrayList.size()) {
                break;
            }
            if (arrayList.get(i) != null) {
                C1418v c1418v = (C1418v) arrayList.get(i);
                float f2 = this.b;
                F f3 = c1418v.g;
                long jMax = Math.max(-1L, Math.min(f3.y + 1, Math.round(f2)));
                f3.H(jMax, c1418v.a);
                c1418v.a = jMax;
            }
            i++;
        }
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            if (arrayList.get(size) == null) {
                arrayList.remove(size);
            }
        }
    }
}
