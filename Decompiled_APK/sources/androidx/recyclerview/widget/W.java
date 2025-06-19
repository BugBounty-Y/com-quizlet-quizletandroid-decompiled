package androidx.recyclerview.widget;

import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;

/* loaded from: classes.dex */
public final class W extends AbstractC1365f0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ W(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public void a() {
        switch (this.a) {
            case 0:
                X x = (X) this.b;
                x.e = x.c.getItemCount();
                C1372j c1372j = x.d;
                ((C1370i) c1372j.e).notifyDataSetChanged();
                c1372j.e();
                break;
            case 1:
                RecyclerViewFragment recyclerViewFragment = (RecyclerViewFragment) this.b;
                if (recyclerViewFragment.f.getAdapter() == null) {
                    recyclerViewFragment.f.setAdapter(recyclerViewFragment.n);
                    recyclerViewFragment.f.setLayoutManager(recyclerViewFragment.m);
                }
                recyclerViewFragment.l.b(recyclerViewFragment.n.getItemCount() > 0);
                break;
            case 2:
                com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a aVar = (com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) this.b;
                aVar.g();
                aVar.notifyDataSetChanged();
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public void b(int i, int i2) {
        switch (this.a) {
            case 0:
                X x = (X) this.b;
                C1372j c1372j = x.d;
                ((C1370i) c1372j.e).notifyItemRangeChanged(i + c1372j.f(x), i2, null);
                break;
            case 1:
                a();
                break;
            case 2:
                com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a aVar = (com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) this.b;
                int iB = aVar.c.b((i2 + i) - 1);
                int iB2 = aVar.c.b(i);
                aVar.notifyItemRangeChanged(iB2, (iB - iB2) + 1);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public void c(int i, int i2, Object obj) {
        switch (this.a) {
            case 0:
                X x = (X) this.b;
                C1372j c1372j = x.d;
                ((C1370i) c1372j.e).notifyItemRangeChanged(i + c1372j.f(x), i2, obj);
                break;
            case 1:
                a();
                break;
            default:
                super.c(i, i2, obj);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public final void d(int i, int i2) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                X x = (X) obj;
                x.e += i2;
                C1372j c1372j = x.d;
                ((C1370i) c1372j.e).notifyItemRangeInserted(i + c1372j.f(x), i2);
                if (x.e > 0 && x.c.getStateRestorationPolicy() == EnumC1359c0.b) {
                    x.d.e();
                    break;
                }
                break;
            case 1:
                a();
                break;
            case 2:
                com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a aVar = (com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) obj;
                if (i + i2 >= ((AbstractC1361d0) aVar.b).getItemCount()) {
                    aVar.g();
                    aVar.notifyDataSetChanged();
                    break;
                }
                break;
            default:
                String str = OldHomeFragment.d1;
                ((OldHomeFragment) obj).X().n0(0);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public void e(int i, int i2) {
        switch (this.a) {
            case 0:
                X x = (X) this.b;
                C1372j c1372j = x.d;
                int iF = c1372j.f(x);
                ((C1370i) c1372j.e).notifyItemMoved(i + iF, i2 + iF);
                break;
            case 1:
                a();
                break;
            case 2:
                ((com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) this.b).notifyDataSetChanged();
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public void f(int i, int i2) {
        switch (this.a) {
            case 0:
                X x = (X) this.b;
                x.e -= i2;
                C1372j c1372j = x.d;
                ((C1370i) c1372j.e).notifyItemRangeRemoved(i + c1372j.f(x), i2);
                if (x.e < 1 && x.c.getStateRestorationPolicy() == EnumC1359c0.b) {
                    x.d.e();
                    break;
                }
                break;
            case 1:
                a();
                break;
            case 2:
                com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a aVar = (com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) this.b;
                aVar.g();
                aVar.notifyDataSetChanged();
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1365f0
    public void g() {
        switch (this.a) {
            case 0:
                ((X) this.b).d.e();
                break;
        }
    }
}
