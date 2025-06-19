package androidx.recyclerview.widget;

import android.view.View;
import android.view.ViewPropertyAnimator;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.WeakHashMap;

/* renamed from: androidx.recyclerview.widget.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC1355a0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ RecyclerView b;

    public /* synthetic */ RunnableC1355a0(RecyclerView recyclerView, int i) {
        this.a = i;
        this.b = recyclerView;
    }

    @Override // java.lang.Runnable
    public final void run() {
        RecyclerView recyclerView = this.b;
        switch (this.a) {
            case 0:
                if (recyclerView.u && !recyclerView.isLayoutRequested()) {
                    if (!recyclerView.s) {
                        recyclerView.requestLayout();
                        break;
                    } else if (!recyclerView.x) {
                        recyclerView.q();
                        break;
                    } else {
                        recyclerView.w = true;
                        break;
                    }
                }
                break;
            default:
                AbstractC1373j0 abstractC1373j0 = recyclerView.M;
                if (abstractC1373j0 != null) {
                    C1386q c1386q = (C1386q) abstractC1373j0;
                    ArrayList arrayList = c1386q.h;
                    boolean zIsEmpty = arrayList.isEmpty();
                    ArrayList arrayList2 = c1386q.j;
                    boolean zIsEmpty2 = arrayList2.isEmpty();
                    ArrayList arrayList3 = c1386q.k;
                    boolean zIsEmpty3 = arrayList3.isEmpty();
                    ArrayList arrayList4 = c1386q.i;
                    boolean zIsEmpty4 = arrayList4.isEmpty();
                    if (!zIsEmpty || !zIsEmpty2 || !zIsEmpty4 || !zIsEmpty3) {
                        Iterator it2 = arrayList.iterator();
                        while (true) {
                            boolean zHasNext = it2.hasNext();
                            long j = c1386q.d;
                            if (zHasNext) {
                                F0 f0 = (F0) it2.next();
                                View view = f0.itemView;
                                ViewPropertyAnimator viewPropertyAnimatorAnimate = view.animate();
                                c1386q.q.add(f0);
                                viewPropertyAnimatorAnimate.setDuration(j).alpha(DefinitionKt.NO_Float_VALUE).setListener(new C1376l(c1386q, f0, viewPropertyAnimatorAnimate, view)).start();
                                arrayList = arrayList;
                            } else {
                                arrayList.clear();
                                if (!zIsEmpty2) {
                                    ArrayList arrayList5 = new ArrayList();
                                    arrayList5.addAll(arrayList2);
                                    c1386q.m.add(arrayList5);
                                    arrayList2.clear();
                                    RunnableC1374k runnableC1374k = new RunnableC1374k(0, c1386q, arrayList5);
                                    if (zIsEmpty) {
                                        runnableC1374k.run();
                                    } else {
                                        View view2 = ((C1384p) arrayList5.get(0)).a.itemView;
                                        WeakHashMap weakHashMap = androidx.core.view.V.a;
                                        view2.postOnAnimationDelayed(runnableC1374k, j);
                                    }
                                }
                                if (!zIsEmpty3) {
                                    ArrayList arrayList6 = new ArrayList();
                                    arrayList6.addAll(arrayList3);
                                    c1386q.n.add(arrayList6);
                                    arrayList3.clear();
                                    RunnableC1374k runnableC1374k2 = new RunnableC1374k(1, c1386q, arrayList6);
                                    if (zIsEmpty) {
                                        runnableC1374k2.run();
                                    } else {
                                        View view3 = ((C1382o) arrayList6.get(0)).a.itemView;
                                        WeakHashMap weakHashMap2 = androidx.core.view.V.a;
                                        view3.postOnAnimationDelayed(runnableC1374k2, j);
                                    }
                                }
                                if (!zIsEmpty4) {
                                    ArrayList arrayList7 = new ArrayList();
                                    arrayList7.addAll(arrayList4);
                                    c1386q.l.add(arrayList7);
                                    arrayList4.clear();
                                    RunnableC1374k runnableC1374k3 = new RunnableC1374k(2, c1386q, arrayList7);
                                    if (zIsEmpty && zIsEmpty2 && zIsEmpty3) {
                                        runnableC1374k3.run();
                                    } else {
                                        if (zIsEmpty) {
                                            j = 0;
                                        }
                                        long jMax = Math.max(!zIsEmpty2 ? c1386q.e : 0L, zIsEmpty3 ? 0L : c1386q.f) + j;
                                        View view4 = ((F0) arrayList7.get(0)).itemView;
                                        WeakHashMap weakHashMap3 = androidx.core.view.V.a;
                                        view4.postOnAnimationDelayed(runnableC1374k3, jMax);
                                    }
                                }
                            }
                        }
                    }
                }
                recyclerView.x1 = false;
                break;
        }
    }
}
