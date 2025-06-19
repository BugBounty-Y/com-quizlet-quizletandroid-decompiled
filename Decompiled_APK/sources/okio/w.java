package okio;

import java.util.RandomAccess;
import kotlin.collections.AbstractC4916g;

/* loaded from: classes3.dex */
public final class w extends AbstractC4916g implements RandomAccess {
    public static final /* synthetic */ int d = 0;
    public final k[] b;
    public final int[] c;

    public w(k[] kVarArr, int[] iArr) {
        this.b = kVarArr;
        this.c = iArr;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.b.length;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final /* bridge */ boolean contains(Object obj) {
        if (obj instanceof k) {
            return super.contains((k) obj);
        }
        return false;
    }

    @Override // java.util.List
    public final Object get(int i) {
        return this.b[i];
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final /* bridge */ int indexOf(Object obj) {
        if (obj instanceof k) {
            return super.indexOf((k) obj);
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final /* bridge */ int lastIndexOf(Object obj) {
        if (obj instanceof k) {
            return super.lastIndexOf((k) obj);
        }
        return -1;
    }
}
