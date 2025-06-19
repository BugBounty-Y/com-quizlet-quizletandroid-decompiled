package androidx.appcompat.widget;

import android.database.DataSetObserver;
import androidx.viewpager.widget.ViewPager;

/* loaded from: classes.dex */
public final class D0 extends DataSetObserver {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ D0(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.database.DataSetObserver
    public final void onChanged() {
        switch (this.a) {
            case 0:
                G0 g0 = (G0) this.b;
                if (g0.z.isShowing()) {
                    g0.f();
                    break;
                }
                break;
            case 1:
                j1 j1Var = (j1) this.b;
                j1Var.a = true;
                j1Var.notifyDataSetChanged();
                break;
            case 2:
                ((ViewPager) this.b).e();
                break;
            case 3:
                ((com.commonsware.cwac.merge.c) this.b).notifyDataSetChanged();
                break;
            default:
                ((com.google.android.material.tabs.l) this.b).k();
                break;
        }
    }

    @Override // android.database.DataSetObserver
    public final void onInvalidated() {
        switch (this.a) {
            case 0:
                ((G0) this.b).dismiss();
                break;
            case 1:
                j1 j1Var = (j1) this.b;
                j1Var.a = false;
                j1Var.notifyDataSetInvalidated();
                break;
            case 2:
                ((ViewPager) this.b).e();
                break;
            case 3:
                ((com.commonsware.cwac.merge.c) this.b).notifyDataSetInvalidated();
                break;
            default:
                ((com.google.android.material.tabs.l) this.b).k();
                break;
        }
    }
}
