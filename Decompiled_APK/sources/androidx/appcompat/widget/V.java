package androidx.appcompat.widget;

import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1373j0;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import java.util.ArrayList;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class V implements Runnable {
    public final /* synthetic */ int a;
    public final int b;
    public final Object c;
    public final Object d;

    public /* synthetic */ V(Object obj, int i, Object obj2, int i2) {
        this.a = i2;
        this.d = obj;
        this.b = i;
        this.c = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        androidx.concurrent.futures.i iVar;
        ArrayList arrayList;
        int iDecrementAndGet;
        switch (this.a) {
            case 0:
                ((TextView) this.c).setTypeface((Typeface) this.d, this.b);
                return;
            case 1:
                ((androidx.browser.customtabs.g) this.d).b.e(this.b, (Bundle) this.c);
                return;
            case 2:
                int i = this.b;
                com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) this.c;
                androidx.camera.core.impl.utils.futures.l lVar = (androidx.camera.core.impl.utils.futures.l) this.d;
                AtomicInteger atomicInteger = lVar.d;
                ArrayList arrayList2 = lVar.b;
                boolean zIsDone = lVar.isDone();
                boolean z = lVar.c;
                if (zIsDone || arrayList2 == null) {
                    AbstractC3242q6.h("Future was done before all dependencies completed", z);
                    return;
                }
                try {
                    try {
                        try {
                            try {
                                AbstractC3242q6.h("Tried to set value from future which is not done", eVar.isDone());
                                arrayList2.set(i, androidx.camera.core.impl.utils.futures.i.b(eVar));
                                iDecrementAndGet = atomicInteger.decrementAndGet();
                                AbstractC3242q6.h("Less than 0 remaining futures", iDecrementAndGet >= 0);
                            } catch (Error e) {
                                lVar.f.d(e);
                                int iDecrementAndGet2 = atomicInteger.decrementAndGet();
                                AbstractC3242q6.h("Less than 0 remaining futures", iDecrementAndGet2 >= 0);
                                if (iDecrementAndGet2 != 0) {
                                    return;
                                }
                                ArrayList arrayList3 = lVar.b;
                                if (arrayList3 != null) {
                                    iVar = lVar.f;
                                    arrayList = new ArrayList(arrayList3);
                                }
                            }
                        } catch (RuntimeException e2) {
                            if (z) {
                                lVar.f.d(e2);
                            }
                            int iDecrementAndGet3 = atomicInteger.decrementAndGet();
                            AbstractC3242q6.h("Less than 0 remaining futures", iDecrementAndGet3 >= 0);
                            if (iDecrementAndGet3 != 0) {
                                return;
                            }
                            ArrayList arrayList4 = lVar.b;
                            if (arrayList4 != null) {
                                iVar = lVar.f;
                                arrayList = new ArrayList(arrayList4);
                            }
                        }
                    } catch (CancellationException unused) {
                        if (z) {
                            lVar.cancel(false);
                        }
                        int iDecrementAndGet4 = atomicInteger.decrementAndGet();
                        AbstractC3242q6.h("Less than 0 remaining futures", iDecrementAndGet4 >= 0);
                        if (iDecrementAndGet4 != 0) {
                            return;
                        }
                        ArrayList arrayList5 = lVar.b;
                        if (arrayList5 != null) {
                            iVar = lVar.f;
                            arrayList = new ArrayList(arrayList5);
                        }
                    } catch (ExecutionException e3) {
                        if (z) {
                            lVar.f.d(e3.getCause());
                        }
                        int iDecrementAndGet5 = atomicInteger.decrementAndGet();
                        AbstractC3242q6.h("Less than 0 remaining futures", iDecrementAndGet5 >= 0);
                        if (iDecrementAndGet5 != 0) {
                            return;
                        }
                        ArrayList arrayList6 = lVar.b;
                        if (arrayList6 != null) {
                            iVar = lVar.f;
                            arrayList = new ArrayList(arrayList6);
                        }
                    }
                    if (iDecrementAndGet == 0) {
                        ArrayList arrayList7 = lVar.b;
                        if (arrayList7 != null) {
                            iVar = lVar.f;
                            arrayList = new ArrayList(arrayList7);
                            iVar.b(arrayList);
                            return;
                        }
                        AbstractC3242q6.h(null, lVar.isDone());
                        return;
                    }
                    return;
                } catch (Throwable th) {
                    int iDecrementAndGet6 = atomicInteger.decrementAndGet();
                    AbstractC3242q6.h("Less than 0 remaining futures", iDecrementAndGet6 >= 0);
                    if (iDecrementAndGet6 == 0) {
                        ArrayList arrayList8 = lVar.b;
                        if (arrayList8 != null) {
                            lVar.f.b(new ArrayList(arrayList8));
                        } else {
                            AbstractC3242q6.h(null, lVar.isDone());
                        }
                    }
                    throw th;
                }
            case 3:
                androidx.recyclerview.widget.L l = (androidx.recyclerview.widget.L) this.d;
                RecyclerView recyclerView = l.r;
                if (recyclerView == null || !recyclerView.s) {
                    return;
                }
                androidx.recyclerview.widget.G g = (androidx.recyclerview.widget.G) this.c;
                if (g.k) {
                    return;
                }
                androidx.recyclerview.widget.F0 f0 = g.e;
                if (f0.getAbsoluteAdapterPosition() != -1) {
                    AbstractC1373j0 itemAnimator = l.r.getItemAnimator();
                    if (itemAnimator == null || !itemAnimator.f()) {
                        ArrayList arrayList9 = l.p;
                        int size = arrayList9.size();
                        for (int i2 = 0; i2 < size; i2++) {
                            if (((androidx.recyclerview.widget.G) arrayList9.get(i2)).l) {
                            }
                        }
                        l.m.onSwiped(f0, this.b);
                        return;
                    }
                    l.r.post(this);
                    return;
                }
                return;
            case 4:
                ((androidx.work.impl.background.systemalarm.h) this.c).a(this.b, (Intent) this.d);
                return;
            default:
                ((BottomSheetBehavior) this.d).M((View) this.c, this.b, false);
                return;
        }
    }

    public /* synthetic */ V(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = i;
    }

    public /* synthetic */ V(Object obj, Object obj2, int i, int i2, boolean z) {
        this.a = i2;
        this.d = obj;
        this.c = obj2;
        this.b = i;
    }
}
