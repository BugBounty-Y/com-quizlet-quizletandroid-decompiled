package androidx.camera.core;

/* renamed from: androidx.camera.core.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0156h {
    public final androidx.camera.core.processing.l a;

    public C0156h(androidx.camera.core.processing.l lVar) {
        if (lVar == null) {
            throw new NullPointerException("Null surfaceOutput");
        }
        this.a = lVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0156h)) {
            return false;
        }
        C0156h c0156h = (C0156h) obj;
        c0156h.getClass();
        return this.a.equals(c0156h.a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ (-721379959);
    }

    public final String toString() {
        return "Event{eventCode=0, surfaceOutput=" + this.a + "}";
    }
}
