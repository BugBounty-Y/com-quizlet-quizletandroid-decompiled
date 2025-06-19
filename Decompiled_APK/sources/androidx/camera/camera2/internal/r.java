package androidx.camera.camera2.internal;

import android.text.TextUtils;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C b;
    public final /* synthetic */ ArrayList c;

    public /* synthetic */ r(C c, ArrayList arrayList, int i) {
        this.a = i;
        this.b = c;
        this.c = arrayList;
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.quizlet.data.repository.course.membership.c cVar;
        switch (this.a) {
            case 0:
                C c = this.b;
                ArrayList arrayList = this.c;
                c.getClass();
                ArrayList arrayList2 = new ArrayList();
                Iterator it2 = arrayList.iterator();
                boolean z = false;
                while (it2.hasNext()) {
                    C0125b c0125b = (C0125b) it2.next();
                    if (c.a.d(c0125b.a)) {
                        c.a.a.remove(c0125b.a);
                        arrayList2.add(c0125b.a);
                        if (c0125b.b == androidx.camera.core.X.class) {
                            z = true;
                        }
                    }
                }
                if (arrayList2.isEmpty()) {
                    return;
                }
                c.t("Use cases [" + TextUtils.join(", ", arrayList2) + "] now DETACHED for camera");
                if (z) {
                    c.g.h.getClass();
                }
                c.p();
                if (c.a.c().isEmpty()) {
                    c.g.l.a = false;
                } else {
                    c.L();
                }
                if (!c.a.b().isEmpty()) {
                    c.K();
                    c.D();
                    if (c.H == 9) {
                        c.B();
                        return;
                    }
                    return;
                }
                c.g.i();
                c.D();
                c.g.m(false);
                c.l = c.z();
                c.t("Closing camera.");
                switch (AbstractC0147y.k(c.H)) {
                    case 3:
                        AbstractC3242q6.h(null, c.j == null);
                        c.F(3);
                        return;
                    case 4:
                    default:
                        c.t("close() ignored due to being in state: ".concat(AbstractC0147y.l(c.H)));
                        return;
                    case 5:
                    case 6:
                    case 7:
                        if (c.h.a() || ((cVar = (com.quizlet.data.repository.course.membership.c) c.G.b) != null && !((AtomicBoolean) cVar.b).get())) {
                            z = true;
                        }
                        c.G.j();
                        c.F(5);
                        if (z) {
                            AbstractC3242q6.h(null, c.m.isEmpty());
                            c.r();
                            return;
                        }
                        return;
                    case 8:
                    case 9:
                        c.F(5);
                        c.q();
                        return;
                }
            default:
                ArrayList arrayList3 = this.c;
                C c2 = this.b;
                C0137n c0137n = c2.g;
                try {
                    c2.H(arrayList3);
                    return;
                } finally {
                    c0137n.i();
                }
        }
    }
}
