package androidx.compose.runtime;

import androidx.collection.C0223v;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A0 implements Iterable, kotlin.jvm.internal.markers.a {
    public int b;
    public int d;
    public int e;
    public boolean g;
    public int h;
    public HashMap j;
    public C0223v k;
    public int[] a = new int[0];
    public Object[] c = new Object[0];
    public final Object f = new Object();
    public ArrayList i = new ArrayList();

    public final int a(C0774b c0774b) {
        if (this.g) {
            r.c("Use active SlotWriter to determine anchor location instead");
        }
        if (!c0774b.a()) {
            AbstractC0805k0.a("Anchor refers to a group that was removed");
        }
        return c0774b.a;
    }

    public final void b() {
        this.j = new HashMap();
    }

    public final C0840z0 e() {
        if (this.g) {
            throw new IllegalStateException("Cannot read while a writer is pending");
        }
        this.e++;
        return new C0840z0(this);
    }

    public final D0 g() {
        if (this.g) {
            r.c("Cannot start a writer when another writer is pending");
        }
        if (this.e > 0) {
            r.c("Cannot start a writer when a reader is pending");
        }
        this.g = true;
        this.h++;
        return new D0(this);
    }

    public final boolean h(C0774b c0774b) {
        int iE;
        return c0774b.a() && (iE = C0.e(this.i, c0774b.a, this.b)) >= 0 && Intrinsics.b(this.i.get(iE), c0774b);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new L(this, 0, this.b);
    }
}
