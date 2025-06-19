package com.mayakapps.kache.collection;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements Iterator, kotlin.jvm.internal.markers.a {
    public final androidx.compose.ui.text.android.selection.f a;
    public final boolean b;
    public int c;
    public final /* synthetic */ c d;

    public a(boolean z, c cVar, androidx.compose.ui.text.android.selection.f parent) {
        this.d = cVar;
        Intrinsics.checkNotNullParameter(parent, "parent");
        this.a = parent;
        this.b = z;
        this.c = z ? parent.c : parent.b;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.c != -1;
    }

    @Override // java.util.Iterator
    public final Object next() {
        int i = this.c;
        if (i == -1) {
            throw new NoSuchElementException();
        }
        boolean z = this.b;
        androidx.compose.ui.text.android.selection.f fVar = this.a;
        this.c = z ? ((int[]) fVar.e)[i] : ((int[]) fVar.d)[i];
        return this.d.b[i];
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
