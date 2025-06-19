package androidx.concurrent.futures;

/* loaded from: classes.dex */
public final class k extends h {
    public final /* synthetic */ l h;

    public k(l lVar) {
        this.h = lVar;
    }

    @Override // androidx.concurrent.futures.h
    public final String i() {
        i iVar = (i) this.h.a.get();
        return iVar == null ? "Completer object has been garbage collected, future will fail soon" : android.support.v4.media.session.a.s(new StringBuilder("tag=["), iVar.a, "]");
    }
}
