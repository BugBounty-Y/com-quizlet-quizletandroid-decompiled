package androidx.recyclerview.widget;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes.dex */
public abstract class V extends AbstractC1361d0 {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public V(AbstractC1361d0 abstractC1361d0) {
        this.b = abstractC1361d0;
        setHasStableIds(abstractC1361d0.hasStableIds());
        com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a aVar = (com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a) this;
        ((AbstractC1361d0) aVar.b).registerAdapterDataObserver(new W(aVar, 2));
    }

    public Object d(int i) {
        return ((C1364f) this.b).f.get(i);
    }

    public void f(List list) {
        ((C1364f) this.b).b(list, null);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public int getItemCount() {
        return ((C1364f) this.b).f.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        switch (this.a) {
            case 1:
                ((AbstractC1361d0) this.b).onAttachedToRecyclerView(recyclerView);
                break;
            default:
                super.onAttachedToRecyclerView(recyclerView);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onDetachedFromRecyclerView(RecyclerView recyclerView) {
        switch (this.a) {
            case 1:
                ((AbstractC1361d0) this.b).onDetachedFromRecyclerView(recyclerView);
                break;
            default:
                super.onDetachedFromRecyclerView(recyclerView);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public boolean onFailedToRecycleView(F0 f0) {
        switch (this.a) {
            case 1:
                return ((AbstractC1361d0) this.b).onFailedToRecycleView(f0);
            default:
                return super.onFailedToRecycleView(f0);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onViewAttachedToWindow(F0 f0) {
        switch (this.a) {
            case 1:
                ((AbstractC1361d0) this.b).onViewAttachedToWindow(f0);
                break;
            default:
                super.onViewAttachedToWindow(f0);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onViewDetachedFromWindow(F0 f0) {
        switch (this.a) {
            case 1:
                ((AbstractC1361d0) this.b).onViewDetachedFromWindow(f0);
                break;
            default:
                super.onViewDetachedFromWindow(f0);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onViewRecycled(F0 f0) {
        switch (this.a) {
            case 1:
                ((AbstractC1361d0) this.b).onViewRecycled(f0);
                break;
            default:
                super.onViewRecycled(f0);
                break;
        }
    }

    public V(AbstractC1358c abstractC1358c) {
        U u = new U(this);
        C1356b c1356b = new C1356b(this);
        synchronized (AbstractC1358c.a) {
            try {
                if (AbstractC1358c.b == null) {
                    AbstractC1358c.b = Executors.newFixedThreadPool(2);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        ExecutorService executorService = AbstractC1358c.b;
        N0 n0 = new N0();
        n0.a = executorService;
        n0.b = abstractC1358c;
        C1364f c1364f = new C1364f(c1356b, n0);
        this.b = c1364f;
        c1364f.d.add(u);
    }
}
