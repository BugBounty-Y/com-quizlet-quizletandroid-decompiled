package androidx.constraintlayout.core.parser;

import java.util.Iterator;

/* loaded from: classes.dex */
public final class g extends b implements Iterable {
    @Override // androidx.constraintlayout.core.parser.b
    /* renamed from: E, reason: merged with bridge method [inline-methods] */
    public final g clone() {
        return (g) super.clone();
    }

    @Override // androidx.constraintlayout.core.parser.b, androidx.constraintlayout.core.parser.c
    public final Object clone() {
        return (g) super.clone();
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        f fVar = new f();
        fVar.b = 0;
        fVar.c = this;
        return fVar;
    }
}
