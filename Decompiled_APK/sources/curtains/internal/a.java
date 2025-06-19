package curtains.internal;

import android.view.View;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.jsoup.nodes.i;

/* loaded from: classes3.dex */
public final class a extends ArrayList {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public a(i iVar, int i) {
        super(i);
        this.b = iVar;
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                View element = (View) obj;
                Intrinsics.checkNotNullParameter(element, "element");
                Iterator it2 = ((b) this.b).a.iterator();
                while (it2.hasNext()) {
                    ((curtains.c) it2.next()).a(element, true);
                }
                return super.add(element);
            default:
                b();
                return super.add(obj);
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean addAll(Collection collection) {
        switch (this.a) {
            case 1:
                b();
                break;
        }
        return super.addAll(collection);
    }

    public void b() {
        ((i) this.b).e = null;
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public void clear() {
        switch (this.a) {
            case 1:
                b();
                super.clear();
                break;
            default:
                super.clear();
                break;
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public /* bridge */ boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                if (obj instanceof View) {
                    return super.contains((View) obj);
                }
                return false;
            default:
                return super.contains(obj);
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public /* bridge */ int indexOf(Object obj) {
        switch (this.a) {
            case 0:
                if (obj instanceof View) {
                    return super.indexOf((View) obj);
                }
                return -1;
            default:
                return super.indexOf(obj);
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public /* bridge */ int lastIndexOf(Object obj) {
        switch (this.a) {
            case 0:
                if (obj instanceof View) {
                    return super.lastIndexOf((View) obj);
                }
                return -1;
            default:
                return super.lastIndexOf(obj);
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public final Object remove(int i) {
        switch (this.a) {
            case 0:
                Object objRemove = super.remove(i);
                Intrinsics.checkNotNullExpressionValue(objRemove, "super.removeAt(index)");
                View view = (View) objRemove;
                Iterator it2 = ((b) this.b).a.iterator();
                while (it2.hasNext()) {
                    ((curtains.c) it2.next()).a(view, false);
                }
                return view;
            default:
                b();
                return super.remove(i);
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean removeAll(Collection collection) {
        switch (this.a) {
            case 1:
                b();
                break;
        }
        return super.removeAll(collection);
    }

    @Override // java.util.ArrayList, java.util.AbstractList
    public void removeRange(int i, int i2) {
        switch (this.a) {
            case 1:
                b();
                super.removeRange(i, i2);
                break;
            default:
                super.removeRange(i, i2);
                break;
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean retainAll(Collection collection) {
        switch (this.a) {
            case 1:
                b();
                break;
        }
        return super.retainAll(collection);
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public Object set(int i, Object obj) {
        switch (this.a) {
            case 1:
                b();
                break;
        }
        return super.set(i, obj);
    }

    public a(b bVar) {
        this.b = bVar;
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public boolean addAll(int i, Collection collection) {
        switch (this.a) {
            case 1:
                b();
                break;
        }
        return super.addAll(i, collection);
    }

    @Override // java.util.ArrayList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                if (obj instanceof View) {
                    return super.remove((View) obj);
                }
                return false;
            default:
                b();
                return super.remove(obj);
        }
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.List
    public void add(int i, Object obj) {
        switch (this.a) {
            case 1:
                b();
                super.add(i, obj);
                break;
            default:
                super.add(i, obj);
                break;
        }
    }
}
