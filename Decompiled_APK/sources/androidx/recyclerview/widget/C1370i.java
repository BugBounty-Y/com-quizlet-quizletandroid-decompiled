package androidx.recyclerview.widget;

import android.view.ViewGroup;
import androidx.appcompat.widget.C0070a;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;

/* renamed from: androidx.recyclerview.widget.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1370i extends AbstractC1361d0 {
    public final C1372j a;

    public C1370i(AbstractC1361d0... abstractC1361d0Arr) {
        this(C1368h.b, abstractC1361d0Arr);
    }

    public final void d(AbstractC1361d0 abstractC1361d0) {
        C1372j c1372j = this.a;
        c1372j.a(c1372j.d.size(), abstractC1361d0);
    }

    public final List f() {
        List list;
        ArrayList arrayList = this.a.d;
        if (arrayList.isEmpty()) {
            list = Collections.EMPTY_LIST;
        } else {
            ArrayList arrayList2 = new ArrayList(arrayList.size());
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(((X) it2.next()).c);
            }
            list = arrayList2;
        }
        return Collections.unmodifiableList(list);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int findRelativeAdapterPositionIn(AbstractC1361d0 abstractC1361d0, F0 f0, int i) {
        C1372j c1372j = this.a;
        X x = (X) ((IdentityHashMap) c1372j.g).get(f0);
        if (x == null) {
            return -1;
        }
        int iF = i - c1372j.f(x);
        AbstractC1361d0 abstractC1361d02 = x.c;
        int itemCount = abstractC1361d02.getItemCount();
        if (iF >= 0 && iF < itemCount) {
            return abstractC1361d02.findRelativeAdapterPositionIn(abstractC1361d0, f0, iF);
        }
        StringBuilder sbW = android.support.v4.media.session.a.w("Detected inconsistent adapter updates. The local position of the view holder maps to ", iF, " which is out of bounds for the adapter with size ", ".Make sure to immediately call notify methods in your adapter when you change the backing dataviewHolder:", itemCount);
        sbW.append(f0);
        sbW.append("adapter:");
        sbW.append(abstractC1361d0);
        throw new IllegalStateException(sbW.toString());
    }

    public final void g(EnumC1359c0 enumC1359c0) {
        super.setStateRestorationPolicy(enumC1359c0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        Iterator it2 = this.a.d.iterator();
        int i = 0;
        while (it2.hasNext()) {
            i += ((X) it2.next()).e;
        }
        return i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        C1372j c1372j = this.a;
        C0070a c0070aI = c1372j.i(i);
        X x = (X) c0070aI.c;
        x.c.getItemId(c0070aI.a);
        x.b.getClass();
        c0070aI.b = false;
        c0070aI.c = null;
        c0070aI.a = -1;
        c1372j.h = c0070aI;
        return -1L;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        C1372j c1372j = this.a;
        C0070a c0070aI = c1372j.i(i);
        X x = (X) c0070aI.c;
        int iC = x.a.c(x.c.getItemViewType(c0070aI.a));
        c0070aI.b = false;
        c0070aI.c = null;
        c0070aI.a = -1;
        c1372j.h = c0070aI;
        return iC;
    }

    public final void h(AbstractC1361d0 abstractC1361d0) {
        C1372j c1372j = this.a;
        int iK = c1372j.k(abstractC1361d0);
        if (iK == -1) {
            return;
        }
        ArrayList arrayList = c1372j.d;
        X x = (X) arrayList.get(iK);
        int iF = c1372j.f(x);
        arrayList.remove(iK);
        ((C1370i) c1372j.e).notifyItemRangeRemoved(iF, x.e);
        Iterator it2 = c1372j.c.iterator();
        while (it2.hasNext()) {
            RecyclerView recyclerView = (RecyclerView) ((WeakReference) it2.next()).get();
            if (recyclerView != null) {
                abstractC1361d0.onDetachedFromRecyclerView(recyclerView);
            }
        }
        x.c.unregisterAdapterDataObserver(x.f);
        x.a.dispose();
        c1372j.e();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onAttachedToRecyclerView(RecyclerView recyclerView) {
        C1372j c1372j = this.a;
        ArrayList arrayList = c1372j.c;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (((WeakReference) it2.next()).get() == recyclerView) {
                return;
            }
        }
        arrayList.add(new WeakReference(recyclerView));
        Iterator it3 = c1372j.d.iterator();
        while (it3.hasNext()) {
            ((X) it3.next()).c.onAttachedToRecyclerView(recyclerView);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        C1372j c1372j = this.a;
        C0070a c0070aI = c1372j.i(i);
        ((IdentityHashMap) c1372j.g).put(f0, (X) c0070aI.c);
        X x = (X) c0070aI.c;
        x.c.bindViewHolder(f0, c0070aI.a);
        c0070aI.b = false;
        c0070aI.c = null;
        c0070aI.a = -1;
        c1372j.h = c0070aI;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        X xA = ((S0) this.a.f).a(i);
        return xA.c.onCreateViewHolder(viewGroup, xA.a.a(i));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onDetachedFromRecyclerView(RecyclerView recyclerView) {
        C1372j c1372j = this.a;
        ArrayList arrayList = c1372j.c;
        int size = arrayList.size() - 1;
        while (true) {
            if (size < 0) {
                break;
            }
            WeakReference weakReference = (WeakReference) arrayList.get(size);
            if (weakReference.get() == null) {
                arrayList.remove(size);
            } else if (weakReference.get() == recyclerView) {
                arrayList.remove(size);
                break;
            }
            size--;
        }
        Iterator it2 = c1372j.d.iterator();
        while (it2.hasNext()) {
            ((X) it2.next()).c.onDetachedFromRecyclerView(recyclerView);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final boolean onFailedToRecycleView(F0 f0) {
        C1372j c1372j = this.a;
        IdentityHashMap identityHashMap = (IdentityHashMap) c1372j.g;
        X x = (X) identityHashMap.get(f0);
        if (x != null) {
            boolean zOnFailedToRecycleView = x.c.onFailedToRecycleView(f0);
            identityHashMap.remove(f0);
            return zOnFailedToRecycleView;
        }
        throw new IllegalStateException("Cannot find wrapper for " + f0 + ", seems like it is not bound by this adapter: " + c1372j);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewAttachedToWindow(F0 f0) {
        this.a.j(f0).c.onViewAttachedToWindow(f0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewDetachedFromWindow(F0 f0) {
        this.a.j(f0).c.onViewDetachedFromWindow(f0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewRecycled(F0 f0) {
        C1372j c1372j = this.a;
        IdentityHashMap identityHashMap = (IdentityHashMap) c1372j.g;
        X x = (X) identityHashMap.get(f0);
        if (x != null) {
            x.c.onViewRecycled(f0);
            identityHashMap.remove(f0);
        } else {
            throw new IllegalStateException("Cannot find wrapper for " + f0 + ", seems like it is not bound by this adapter: " + c1372j);
        }
    }

    public C1370i(C1368h c1368h, AbstractC1361d0... abstractC1361d0Arr) {
        List listAsList = Arrays.asList(abstractC1361d0Arr);
        this.a = new C1372j(this, c1368h);
        Iterator it2 = listAsList.iterator();
        while (it2.hasNext()) {
            d((AbstractC1361d0) it2.next());
        }
        super.setHasStableIds(this.a.b != 1);
    }
}
