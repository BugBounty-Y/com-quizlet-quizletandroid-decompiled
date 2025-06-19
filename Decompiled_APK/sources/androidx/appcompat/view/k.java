package androidx.appcompat.view;

import android.view.View;
import android.view.animation.BaseInterpolator;
import androidx.core.view.C1043d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class k {
    public BaseInterpolator c;
    public AbstractC3267t6 d;
    public boolean e;
    public long b = -1;
    public final j f = new j(this);
    public final ArrayList a = new ArrayList();

    public final void a() {
        if (this.e) {
            Iterator it2 = this.a.iterator();
            while (it2.hasNext()) {
                ((C1043d0) it2.next()).b();
            }
            this.e = false;
        }
    }

    public final void b() {
        View view;
        if (this.e) {
            return;
        }
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            C1043d0 c1043d0 = (C1043d0) it2.next();
            long j = this.b;
            if (j >= 0) {
                c1043d0.c(j);
            }
            BaseInterpolator baseInterpolator = this.c;
            if (baseInterpolator != null && (view = (View) c1043d0.a.get()) != null) {
                view.animate().setInterpolator(baseInterpolator);
            }
            if (this.d != null) {
                c1043d0.d(this.f);
            }
            View view2 = (View) c1043d0.a.get();
            if (view2 != null) {
                view2.animate().start();
            }
        }
        this.e = true;
    }
}
