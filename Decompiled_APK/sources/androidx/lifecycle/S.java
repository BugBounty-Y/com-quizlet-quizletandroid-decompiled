package androidx.lifecycle;

/* loaded from: classes.dex */
public abstract class S {
    public final Z a;
    public boolean b;
    public int c = -1;
    public final /* synthetic */ T d;

    public S(T t, Z z) {
        this.d = t;
        this.a = z;
    }

    public final void a(boolean z) {
        if (z == this.b) {
            return;
        }
        this.b = z;
        int i = z ? 1 : -1;
        T t = this.d;
        int i2 = t.c;
        t.c = i + i2;
        if (!t.d) {
            t.d = true;
            while (true) {
                try {
                    int i3 = t.c;
                    if (i2 == i3) {
                        break;
                    }
                    boolean z2 = i2 == 0 && i3 > 0;
                    boolean z3 = i2 > 0 && i3 == 0;
                    if (z2) {
                        t.h();
                    } else if (z3) {
                        t.i();
                    }
                    i2 = i3;
                } catch (Throwable th) {
                    t.d = false;
                    throw th;
                }
            }
            t.d = false;
        }
        if (this.b) {
            t.c(this);
        }
    }

    public void b() {
    }

    public boolean c(J j) {
        return false;
    }

    public abstract boolean e();
}
