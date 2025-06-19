package androidx.viewpager.widget;

import android.database.DataSetObservable;
import android.database.DataSetObserver;
import android.os.Bundle;
import android.os.Parcelable;

/* loaded from: classes.dex */
public abstract class a {
    public final DataSetObservable a = new DataSetObservable();
    public DataSetObserver b;

    public abstract void a(ViewPager viewPager, int i, Object obj);

    public abstract void b();

    public abstract int c();

    public int d(Object obj) {
        return -1;
    }

    public abstract String e(int i);

    public abstract Object f(ViewPager viewPager, int i);

    public abstract void g(Parcelable parcelable, ClassLoader classLoader);

    public abstract Bundle h();

    public abstract void i(ViewPager viewPager);
}
