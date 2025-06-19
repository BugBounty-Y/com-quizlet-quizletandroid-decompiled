package androidx.fragment.app;

import android.view.View;
import androidx.recyclerview.widget.AbstractC1358c;
import androidx.recyclerview.widget.C1360d;
import androidx.recyclerview.widget.C1364f;
import androidx.recyclerview.widget.RunnableC1374k;
import java.util.ArrayList;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class y0 implements Runnable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ List c;
    public final /* synthetic */ List d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public y0(int i, ArrayList arrayList, ArrayList arrayList2, ArrayList arrayList3, ArrayList arrayList4) {
        this.b = i;
        this.c = arrayList;
        this.d = arrayList2;
        this.e = arrayList3;
        this.f = arrayList4;
    }

    @Override // java.lang.Runnable
    public final void run() {
        Object obj = this.f;
        switch (this.a) {
            case 0:
                for (int i = 0; i < this.b; i++) {
                    View view = (View) ((ArrayList) this.c).get(i);
                    String str = (String) ((ArrayList) this.d).get(i);
                    WeakHashMap weakHashMap = androidx.core.view.V.a;
                    androidx.core.view.L.n(view, str);
                    androidx.core.view.L.n((View) ((ArrayList) this.e).get(i), (String) ((ArrayList) obj).get(i));
                }
                break;
            default:
                ((C1364f) obj).c.execute(new RunnableC1374k(3, this, AbstractC1358c.c(new C1360d(this))));
                break;
        }
    }

    public y0(C1364f c1364f, List list, List list2, int i, Runnable runnable) {
        this.f = c1364f;
        this.c = list;
        this.d = list2;
        this.b = i;
        this.e = runnable;
    }
}
