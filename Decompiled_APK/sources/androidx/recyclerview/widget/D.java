package androidx.recyclerview.widget;

import android.os.Trace;
import androidx.collection.C0210h;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class D implements Runnable {
    public static final ThreadLocal e = new ThreadLocal();
    public static final r f = new r(1);
    public long b;
    public long c;
    public final ArrayList a = new ArrayList();
    public final ArrayList d = new ArrayList();

    public static F0 c(RecyclerView recyclerView, int i, long j) {
        int iC = recyclerView.f.C();
        for (int i2 = 0; i2 < iC; i2++) {
            F0 f0P = RecyclerView.P(recyclerView.f.B(i2));
            if (f0P.mPosition == i && !f0P.isInvalid()) {
                return null;
            }
        }
        v0 v0Var = recyclerView.c;
        if (j == Long.MAX_VALUE) {
            try {
                if (androidx.core.os.h.a()) {
                    Trace.beginSection("RV Prefetch forced - needed next frame");
                }
            } catch (Throwable th) {
                recyclerView.X(false);
                Trace.endSection();
                throw th;
            }
        }
        recyclerView.W();
        F0 f0K = v0Var.k(i, j);
        if (f0K != null) {
            if (!f0K.isBound() || f0K.isInvalid()) {
                v0Var.a(f0K, false);
            } else {
                v0Var.h(f0K.itemView);
            }
        }
        recyclerView.X(false);
        Trace.endSection();
        return f0K;
    }

    public final void a(RecyclerView recyclerView, int i, int i2) {
        if (recyclerView.s) {
            if (RecyclerView.M1 && !this.a.contains(recyclerView)) {
                throw new IllegalStateException("attempting to post unregistered view!");
            }
            if (this.b == 0) {
                this.b = recyclerView.getNanoTime();
                recyclerView.post(this);
            }
        }
        C0210h c0210h = recyclerView.q1;
        c0210h.a = i;
        c0210h.b = i2;
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00ce  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(long r18) {
        /*
            Method dump skipped, instructions count: 335
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.D.b(long):void");
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            Trace.beginSection("RV Prefetch");
            ArrayList arrayList = this.a;
            if (!arrayList.isEmpty()) {
                int size = arrayList.size();
                long jMax = 0;
                for (int i = 0; i < size; i++) {
                    RecyclerView recyclerView = (RecyclerView) arrayList.get(i);
                    if (recyclerView.getWindowVisibility() == 0) {
                        jMax = Math.max(recyclerView.getDrawingTime(), jMax);
                    }
                }
                if (jMax != 0) {
                    b(TimeUnit.MILLISECONDS.toNanos(jMax) + this.c);
                }
            }
        } finally {
            this.b = 0L;
            Trace.endSection();
        }
    }
}
