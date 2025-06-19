package androidx.appcompat.view.menu;

import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class i extends BaseAdapter {
    public int a = -1;
    public final /* synthetic */ j b;

    public i(j jVar) {
        this.b = jVar;
        a();
    }

    public final void a() {
        n nVar = this.b.c;
        p pVar = nVar.v;
        if (pVar != null) {
            nVar.i();
            ArrayList arrayList = nVar.j;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                if (((p) arrayList.get(i)) == pVar) {
                    this.a = i;
                    return;
                }
            }
        }
        this.a = -1;
    }

    @Override // android.widget.Adapter
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    public final p getItem(int i) {
        j jVar = this.b;
        n nVar = jVar.c;
        nVar.i();
        ArrayList arrayList = nVar.j;
        jVar.getClass();
        int i2 = this.a;
        if (i2 >= 0 && i >= i2) {
            i++;
        }
        return (p) arrayList.get(i);
    }

    @Override // android.widget.Adapter
    public final int getCount() {
        j jVar = this.b;
        n nVar = jVar.c;
        nVar.i();
        int size = nVar.j.size();
        jVar.getClass();
        return this.a < 0 ? size : size - 1;
    }

    @Override // android.widget.Adapter
    public final long getItemId(int i) {
        return i;
    }

    @Override // android.widget.Adapter
    public final View getView(int i, View view, ViewGroup viewGroup) {
        if (view == null) {
            view = this.b.b.inflate(R.layout.abc_list_menu_item_layout, viewGroup, false);
        }
        ((A) view).d(getItem(i));
        return view;
    }

    @Override // android.widget.BaseAdapter
    public final void notifyDataSetChanged() {
        a();
        super.notifyDataSetChanged();
    }
}
