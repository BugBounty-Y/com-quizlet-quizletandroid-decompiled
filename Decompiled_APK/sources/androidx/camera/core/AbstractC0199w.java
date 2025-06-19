package androidx.camera.core;

import android.media.Image;
import java.util.HashSet;
import java.util.Iterator;

/* renamed from: androidx.camera.core.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0199w implements O {
    public final O b;
    public final Object a = new Object();
    public final HashSet c = new HashSet();

    public AbstractC0199w(O o) {
        this.b = o;
    }

    @Override // androidx.camera.core.O
    public M N() {
        return this.b.N();
    }

    @Override // androidx.camera.core.O
    public final Image T() {
        return this.b.T();
    }

    public final void a(InterfaceC0198v interfaceC0198v) {
        synchronized (this.a) {
            this.c.add(interfaceC0198v);
        }
    }

    @Override // androidx.camera.core.O
    public int b() {
        return this.b.b();
    }

    @Override // java.lang.AutoCloseable
    public void close() {
        HashSet hashSet;
        this.b.close();
        synchronized (this.a) {
            hashSet = new HashSet(this.c);
        }
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            ((InterfaceC0198v) it2.next()).a(this);
        }
    }

    @Override // androidx.camera.core.O
    public int getWidth() {
        return this.b.getWidth();
    }

    @Override // androidx.camera.core.O
    public final int m() {
        return this.b.m();
    }

    @Override // androidx.camera.core.O
    public final com.quizlet.data.repository.school.membership.a[] o() {
        return this.b.o();
    }
}
