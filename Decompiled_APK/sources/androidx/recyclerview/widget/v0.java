package androidx.recyclerview.widget;

import android.util.SparseArray;
import android.view.View;
import androidx.collection.C0210h;
import androidx.core.view.C1038b;
import com.google.android.gms.internal.mlkit_vision_barcode.G6;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public final class v0 {
    public final ArrayList a;
    public ArrayList b;
    public final ArrayList c;
    public final List d;
    public int e;
    public int f;
    public u0 g;
    public final /* synthetic */ RecyclerView h;

    public v0(RecyclerView recyclerView) {
        this.h = recyclerView;
        ArrayList arrayList = new ArrayList();
        this.a = arrayList;
        this.b = null;
        this.c = new ArrayList();
        this.d = Collections.unmodifiableList(arrayList);
        this.e = 2;
        this.f = 2;
    }

    public final void a(F0 f0, boolean z) {
        RecyclerView.m(f0);
        View view = f0.itemView;
        RecyclerView recyclerView = this.h;
        H0 h0 = recyclerView.y1;
        if (h0 != null) {
            G0 g0 = h0.e;
            androidx.core.view.V.o(view, g0 != null ? (C1038b) g0.e.remove(view) : null);
        }
        if (z) {
            ArrayList arrayList = recyclerView.o;
            if (arrayList.size() > 0) {
                arrayList.get(0).getClass();
                throw new ClassCastException();
            }
            AbstractC1361d0 abstractC1361d0 = recyclerView.m;
            if (abstractC1361d0 != null) {
                abstractC1361d0.onViewRecycled(f0);
            }
            if (recyclerView.r1 != null) {
                recyclerView.g.n(f0);
            }
            if (RecyclerView.N1) {
                Objects.toString(f0);
            }
        }
        f0.mBindingAdapter = null;
        f0.mOwnerRecyclerView = null;
        u0 u0VarC = c();
        u0VarC.getClass();
        int itemViewType = f0.getItemViewType();
        ArrayList arrayList2 = u0VarC.a(itemViewType).a;
        if (((t0) u0VarC.a.get(itemViewType)).b <= arrayList2.size()) {
            G6.b(f0.itemView);
        } else {
            if (RecyclerView.M1 && arrayList2.contains(f0)) {
                throw new IllegalArgumentException("this scrap item already exists");
            }
            f0.resetInternal();
            arrayList2.add(f0);
        }
    }

    public final int b(int i) {
        RecyclerView recyclerView = this.h;
        if (i >= 0 && i < recyclerView.r1.b()) {
            return !recyclerView.r1.g ? i : recyclerView.e.g(i, 0);
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "invalid position ", ". State item count is ");
        sbV.append(recyclerView.r1.b());
        sbV.append(recyclerView.D());
        throw new IndexOutOfBoundsException(sbV.toString());
    }

    public final u0 c() {
        if (this.g == null) {
            u0 u0Var = new u0();
            u0Var.a = new SparseArray();
            u0Var.b = 0;
            u0Var.c = Collections.newSetFromMap(new IdentityHashMap());
            this.g = u0Var;
            d();
        }
        return this.g;
    }

    public final void d() {
        RecyclerView recyclerView;
        AbstractC1361d0 abstractC1361d0;
        u0 u0Var = this.g;
        if (u0Var == null || (abstractC1361d0 = (recyclerView = this.h).m) == null || !recyclerView.s) {
            return;
        }
        u0Var.c.add(abstractC1361d0);
    }

    public final void e(AbstractC1361d0 abstractC1361d0, boolean z) {
        u0 u0Var = this.g;
        if (u0Var == null) {
            return;
        }
        Set set = u0Var.c;
        set.remove(abstractC1361d0);
        if (set.size() != 0 || z) {
            return;
        }
        int i = 0;
        while (true) {
            SparseArray sparseArray = u0Var.a;
            if (i >= sparseArray.size()) {
                return;
            }
            ArrayList arrayList = ((t0) sparseArray.get(sparseArray.keyAt(i))).a;
            for (int i2 = 0; i2 < arrayList.size(); i2++) {
                G6.b(((F0) arrayList.get(i2)).itemView);
            }
            i++;
        }
    }

    public final void f() {
        ArrayList arrayList = this.c;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            g(size);
        }
        arrayList.clear();
        if (RecyclerView.R1) {
            C0210h c0210h = this.h.q1;
            int[] iArr = c0210h.c;
            if (iArr != null) {
                Arrays.fill(iArr, -1);
            }
            c0210h.d = 0;
        }
    }

    public final void g(int i) {
        boolean z = RecyclerView.M1;
        ArrayList arrayList = this.c;
        F0 f0 = (F0) arrayList.get(i);
        if (RecyclerView.N1) {
            Objects.toString(f0);
        }
        a(f0, true);
        arrayList.remove(i);
    }

    public final void h(View view) {
        F0 f0P = RecyclerView.P(view);
        boolean zIsTmpDetached = f0P.isTmpDetached();
        RecyclerView recyclerView = this.h;
        if (zIsTmpDetached) {
            recyclerView.removeDetachedView(view, false);
        }
        if (f0P.isScrap()) {
            f0P.unScrap();
        } else if (f0P.wasReturnedFromScrap()) {
            f0P.clearReturnedFromScrapFlag();
        }
        i(f0P);
        if (recyclerView.M == null || f0P.isRecyclable()) {
            return;
        }
        recyclerView.M.d(f0P);
    }

    /* JADX WARN: Code restructure failed: missing block: B:60:0x00c0, code lost:
    
        r4 = r4 - 1;
     */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00a5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(androidx.recyclerview.widget.F0 r12) {
        /*
            Method dump skipped, instructions count: 321
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.v0.i(androidx.recyclerview.widget.F0):void");
    }

    public final void j(View view) {
        AbstractC1373j0 abstractC1373j0;
        F0 f0P = RecyclerView.P(view);
        boolean zHasAnyOfTheFlags = f0P.hasAnyOfTheFlags(12);
        RecyclerView recyclerView = this.h;
        if (!zHasAnyOfTheFlags && f0P.isUpdated() && (abstractC1373j0 = recyclerView.M) != null) {
            C1386q c1386q = (C1386q) abstractC1373j0;
            if (f0P.getUnmodifiedPayloads().isEmpty() && c1386q.g && !f0P.isInvalid()) {
                if (this.b == null) {
                    this.b = new ArrayList();
                }
                f0P.setScrapContainer(this, true);
                this.b.add(f0P);
                return;
            }
        }
        if (f0P.isInvalid() && !f0P.isRemoved() && !recyclerView.m.hasStableIds()) {
            throw new IllegalArgumentException(androidx.compose.ui.node.B.c(recyclerView, new StringBuilder("Called scrap view with an invalid view. Invalid views cannot be reused from scrap, they should rebound from recycler pool.")));
        }
        f0P.setScrapContainer(this, false);
        this.a.add(f0P);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:188:0x034c  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x034f  */
    /* JADX WARN: Removed duplicated region for block: B:297:0x050e  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x051a  */
    /* JADX WARN: Removed duplicated region for block: B:306:0x0535  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0129  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x014c  */
    /* JADX WARN: Type inference failed for: r10v5, types: [androidx.core.view.b] */
    /* JADX WARN: Type inference failed for: r1v3 */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r3v84 */
    /* JADX WARN: Type inference failed for: r9v5, types: [androidx.core.view.b] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.recyclerview.widget.F0 k(int r31, long r32) {
        /*
            Method dump skipped, instructions count: 1373
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.v0.k(int, long):androidx.recyclerview.widget.F0");
    }

    public final void l(F0 f0) {
        if (f0.mInChangeScrap) {
            this.b.remove(f0);
        } else {
            this.a.remove(f0);
        }
        f0.mScrapContainer = null;
        f0.mInChangeScrap = false;
        f0.clearReturnedFromScrapFlag();
    }

    public final void m() {
        AbstractC1381n0 abstractC1381n0 = this.h.n;
        this.f = this.e + (abstractC1381n0 != null ? abstractC1381n0.j : 0);
        ArrayList arrayList = this.c;
        for (int size = arrayList.size() - 1; size >= 0 && arrayList.size() > this.f; size--) {
            g(size);
        }
    }
}
