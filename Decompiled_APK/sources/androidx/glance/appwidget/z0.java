package androidx.glance.appwidget;

import android.widget.RemoteViews;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class z0 {
    public static final z0 e = new z0(new long[0], new RemoteViews[0], false, 1);
    public final long[] a;
    public final RemoteViews[] b;
    public final boolean c;
    public final int d;

    public z0(long[] jArr, RemoteViews[] remoteViewsArr, boolean z, int i) {
        this.a = jArr;
        this.b = remoteViewsArr;
        this.c = z;
        this.d = i;
        if (jArr.length != remoteViewsArr.length) {
            throw new IllegalArgumentException("RemoteCollectionItems has different number of ids and views");
        }
        if (i < 1) {
            throw new IllegalArgumentException("View type count must be >= 1");
        }
        ArrayList arrayList = new ArrayList(remoteViewsArr.length);
        for (RemoteViews remoteViews : remoteViewsArr) {
            arrayList.add(Integer.valueOf(remoteViews.getLayoutId()));
        }
        int size = CollectionsKt.G(arrayList).size();
        if (size <= this.d) {
            return;
        }
        throw new IllegalArgumentException(("View type count is set to " + this.d + ", but the collection contains " + size + " different layout ids").toString());
    }
}
