package androidx.appcompat.widget;

import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class Q0 extends BaseAdapter {
    public final /* synthetic */ int a = 1;
    public Object b;

    public /* synthetic */ Q0() {
    }

    @Override // android.widget.BaseAdapter, android.widget.ListAdapter
    public boolean areAllItemsEnabled() {
        switch (this.a) {
            case 1:
                return this instanceof com.commonsware.cwac.merge.a;
            default:
                return super.areAllItemsEnabled();
        }
    }

    @Override // android.widget.Adapter
    public final int getCount() {
        switch (this.a) {
            case 0:
                return ((T0) this.b).b.getChildCount();
            default:
                return ((ArrayList) this.b).size();
        }
    }

    @Override // android.widget.Adapter
    public final Object getItem(int i) {
        switch (this.a) {
            case 0:
                ((R0) ((T0) this.b).b.getChildAt(i)).getClass();
                return null;
            default:
                return ((ArrayList) this.b).get(i);
        }
    }

    @Override // android.widget.Adapter
    public final long getItemId(int i) {
        switch (this.a) {
        }
        return i;
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public int getItemViewType(int i) {
        switch (this.a) {
            case 1:
                return i;
            default:
                return super.getItemViewType(i);
        }
    }

    @Override // android.widget.Adapter
    public final View getView(int i, View view, ViewGroup viewGroup) {
        switch (this.a) {
            case 0:
                if (view != null) {
                    getItem(i);
                    throw null;
                }
                getItem(i);
                T0 t0 = (T0) this.b;
                new R0(t0, t0.getContext());
                throw null;
            default:
                View view2 = (View) ((ArrayList) this.b).get(i);
                if (view2 != null) {
                    return view2;
                }
                throw new RuntimeException("You must override newView()!");
        }
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public int getViewTypeCount() {
        switch (this.a) {
            case 1:
                return ((ArrayList) this.b).size();
            default:
                return super.getViewTypeCount();
        }
    }

    @Override // android.widget.BaseAdapter, android.widget.ListAdapter
    public boolean isEnabled(int i) {
        switch (this.a) {
            case 1:
                return this instanceof com.commonsware.cwac.merge.a;
            default:
                return super.isEnabled(i);
        }
    }

    public Q0(T0 t0) {
        this.b = t0;
    }
}
