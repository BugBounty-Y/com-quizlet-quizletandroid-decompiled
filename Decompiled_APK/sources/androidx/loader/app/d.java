package androidx.loader.app;

import androidx.lifecycle.Z;

/* loaded from: classes.dex */
public final class d implements Z {
    public final a a;
    public boolean b = false;

    public d(androidx.loader.content.c cVar, a aVar) {
        this.a = aVar;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        this.b = true;
        this.a.i(obj);
    }

    public final String toString() {
        return this.a.toString();
    }
}
