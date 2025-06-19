package kotlin.collections;

import java.util.AbstractList;
import java.util.List;

/* renamed from: kotlin.collections.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4921l extends AbstractList implements List, kotlin.jvm.internal.markers.c {
    public abstract int a();

    public abstract Object b(int i);

    @Override // java.util.AbstractList, java.util.List
    public final /* bridge */ Object remove(int i) {
        return b(i);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ int size() {
        return a();
    }
}
