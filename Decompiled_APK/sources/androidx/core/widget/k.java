package androidx.core.widget;

import android.os.Parcel;
import android.os.Parcelable;
import android.widget.RemoteViews;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k {
    public final long[] a;
    public final RemoteViews[] b;
    public final boolean c;
    public final int d;

    public k(long[] ids, RemoteViews[] views) {
        Intrinsics.checkNotNullParameter(ids, "ids");
        Intrinsics.checkNotNullParameter(views, "views");
        this.a = ids;
        this.b = views;
        this.c = false;
        this.d = 1;
        if (ids.length != views.length) {
            throw new IllegalArgumentException("RemoteCollectionItems has different number of ids and views");
        }
        ArrayList arrayList = new ArrayList(views.length);
        for (RemoteViews remoteViews : views) {
            arrayList.add(Integer.valueOf(remoteViews.getLayoutId()));
        }
        int size = CollectionsKt.G(arrayList).size();
        if (size > 1) {
            throw new IllegalArgumentException(AbstractC0147y.c(size, "View type count is set to 1, but the collection contains ", " different layout ids").toString());
        }
    }

    public k(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        int i = parcel.readInt();
        long[] jArr = new long[i];
        this.a = jArr;
        parcel.readLongArray(jArr);
        Parcelable.Creator CREATOR = RemoteViews.CREATOR;
        Intrinsics.checkNotNullExpressionValue(CREATOR, "CREATOR");
        RemoteViews[] remoteViewsArr = new RemoteViews[i];
        parcel.readTypedArray(remoteViewsArr, CREATOR);
        Intrinsics.checkNotNullParameter(remoteViewsArr, "<this>");
        for (int i2 = 0; i2 < i; i2++) {
            if (remoteViewsArr[i2] == null) {
                throw new IllegalArgumentException("null element found in " + remoteViewsArr + '.');
            }
        }
        this.b = remoteViewsArr;
        this.c = parcel.readInt() == 1;
        this.d = parcel.readInt();
    }
}
