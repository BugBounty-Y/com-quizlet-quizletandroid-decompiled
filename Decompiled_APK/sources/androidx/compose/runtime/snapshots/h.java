package androidx.compose.runtime.snapshots;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class h {
    public l a;
    public long b;
    public boolean c;
    public int d;

    public h(long j, l lVar) {
        int iA;
        int iNumberOfTrailingZeros;
        this.a = lVar;
        this.b = j;
        com.quizlet.data.repository.classfolder.e eVar = m.a;
        if (j != 0) {
            l lVarD = d();
            long[] jArr = lVarD.d;
            if (jArr != null) {
                j = jArr[0];
            } else {
                long j2 = lVarD.b;
                long j3 = lVarD.c;
                if (j2 != 0) {
                    iNumberOfTrailingZeros = Long.numberOfTrailingZeros(j2);
                } else {
                    long j4 = lVarD.a;
                    if (j4 != 0) {
                        j3 += 64;
                        iNumberOfTrailingZeros = Long.numberOfTrailingZeros(j4);
                    }
                }
                j = iNumberOfTrailingZeros + j3;
            }
            synchronized (m.b) {
                iA = m.e.a(j);
            }
        } else {
            iA = -1;
        }
        this.d = iA;
    }

    public static void q(h hVar) {
        m.a.q(hVar);
    }

    public final void a() {
        synchronized (m.b) {
            b();
            p();
            Unit unit = Unit.a;
        }
    }

    public void b() {
        m.c = m.c.b(g());
    }

    public void c() {
        this.c = true;
        synchronized (m.b) {
            o();
            Unit unit = Unit.a;
        }
    }

    public l d() {
        return this.a;
    }

    public abstract Function1 e();

    public abstract boolean f();

    public long g() {
        return this.b;
    }

    public int h() {
        return 0;
    }

    public abstract Function1 i();

    public final h j() {
        com.quizlet.data.repository.classfolder.e eVar = m.a;
        h hVar = (h) eVar.c();
        eVar.q(this);
        return hVar;
    }

    public abstract void k();

    public abstract void l();

    public abstract void m();

    public abstract void n(z zVar);

    public final void o() {
        int i = this.d;
        if (i >= 0) {
            m.u(i);
            this.d = -1;
        }
    }

    public void p() {
        o();
    }

    public void r(l lVar) {
        this.a = lVar;
    }

    public void s(long j) {
        this.b = j;
    }

    public void t(int i) {
        throw new IllegalStateException("Updating write count is not supported for this snapshot");
    }

    public abstract h u(Function1 function1);
}
