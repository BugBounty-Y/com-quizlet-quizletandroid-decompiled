package com.commonsware.cwac.merge;

import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ListAdapter;
import android.widget.SectionIndexer;
import androidx.appcompat.widget.D0;
import androidx.appcompat.widget.Q0;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class c extends BaseAdapter implements SectionIndexer {
    public final com.quizlet.data.interactor.school.b a;

    public c() {
        com.quizlet.data.interactor.school.b bVar = new com.quizlet.data.interactor.school.b(8, false);
        bVar.b = new ArrayList();
        bVar.c = null;
        this.a = bVar;
    }

    public final void a(ListAdapter listAdapter) {
        ArrayList arrayList = (ArrayList) this.a.b;
        b bVar = new b();
        bVar.a = listAdapter;
        arrayList.add(bVar);
        listAdapter.registerDataSetObserver(new D0(this, 3));
    }

    @Override // android.widget.BaseAdapter, android.widget.ListAdapter
    public final boolean areAllItemsEnabled() {
        return false;
    }

    public final void b(View view) {
        ArrayList arrayList = new ArrayList(1);
        arrayList.add(view);
        Q0 q0 = new Q0();
        q0.b = arrayList;
        a(q0);
    }

    public final ArrayList c() {
        com.quizlet.data.interactor.school.b bVar = this.a;
        if (((ArrayList) bVar.c) == null) {
            bVar.c = new ArrayList();
            Iterator it2 = ((ArrayList) bVar.b).iterator();
            while (it2.hasNext()) {
                b bVar2 = (b) it2.next();
                bVar2.getClass();
                ((ArrayList) bVar.c).add(bVar2.a);
            }
        }
        return (ArrayList) bVar.c;
    }

    @Override // android.widget.Adapter
    public final int getCount() {
        Iterator it2 = c().iterator();
        int count = 0;
        while (it2.hasNext()) {
            count += ((ListAdapter) it2.next()).getCount();
        }
        return count;
    }

    @Override // android.widget.Adapter
    public final Object getItem(int i) {
        Iterator it2 = c().iterator();
        while (it2.hasNext()) {
            ListAdapter listAdapter = (ListAdapter) it2.next();
            int count = listAdapter.getCount();
            if (i < count) {
                return listAdapter.getItem(i);
            }
            i -= count;
        }
        return null;
    }

    @Override // android.widget.Adapter
    public final long getItemId(int i) {
        Iterator it2 = c().iterator();
        while (it2.hasNext()) {
            ListAdapter listAdapter = (ListAdapter) it2.next();
            int count = listAdapter.getCount();
            if (i < count) {
                return listAdapter.getItemId(i);
            }
            i -= count;
        }
        return -1L;
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public final int getItemViewType(int i) {
        Iterator it2 = ((ArrayList) this.a.b).iterator();
        int viewTypeCount = 0;
        while (it2.hasNext()) {
            b bVar = (b) it2.next();
            bVar.getClass();
            ListAdapter listAdapter = bVar.a;
            int count = listAdapter.getCount();
            if (i < count) {
                return listAdapter.getItemViewType(i) + viewTypeCount;
            }
            i -= count;
            viewTypeCount += listAdapter.getViewTypeCount();
        }
        return -1;
    }

    @Override // android.widget.SectionIndexer
    public final int getPositionForSection(int i) {
        Iterator it2 = c().iterator();
        int count = 0;
        while (it2.hasNext()) {
            ListAdapter listAdapter = (ListAdapter) it2.next();
            if (listAdapter instanceof SectionIndexer) {
                SectionIndexer sectionIndexer = (SectionIndexer) listAdapter;
                Object[] sections = sectionIndexer.getSections();
                int length = sections != null ? sections.length : 0;
                if (i < length) {
                    return sectionIndexer.getPositionForSection(i) + count;
                }
                if (sections != null) {
                    i -= length;
                }
            }
            count += listAdapter.getCount();
        }
        return 0;
    }

    @Override // android.widget.SectionIndexer
    public final int getSectionForPosition(int i) {
        Object[] sections;
        Iterator it2 = c().iterator();
        int length = 0;
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            ListAdapter listAdapter = (ListAdapter) it2.next();
            int count = listAdapter.getCount();
            if (i >= count) {
                if ((listAdapter instanceof SectionIndexer) && (sections = ((SectionIndexer) listAdapter).getSections()) != null) {
                    length += sections.length;
                }
                i -= count;
            } else if (listAdapter instanceof SectionIndexer) {
                return ((SectionIndexer) listAdapter).getSectionForPosition(i) + length;
            }
        }
        return 0;
    }

    @Override // android.widget.SectionIndexer
    public final Object[] getSections() {
        Object[] sections;
        ArrayList arrayList = new ArrayList();
        Iterator it2 = c().iterator();
        while (it2.hasNext()) {
            ListAdapter listAdapter = (ListAdapter) it2.next();
            if ((listAdapter instanceof SectionIndexer) && (sections = ((SectionIndexer) listAdapter).getSections()) != null) {
                Collections.addAll(arrayList, sections);
            }
        }
        return arrayList.size() == 0 ? new String[0] : arrayList.toArray(new Object[0]);
    }

    @Override // android.widget.Adapter
    public final View getView(int i, View view, ViewGroup viewGroup) {
        Iterator it2 = c().iterator();
        while (it2.hasNext()) {
            ListAdapter listAdapter = (ListAdapter) it2.next();
            int count = listAdapter.getCount();
            if (i < count) {
                return listAdapter.getView(i, view, viewGroup);
            }
            i -= count;
        }
        return null;
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public final int getViewTypeCount() {
        Iterator it2 = ((ArrayList) this.a.b).iterator();
        int viewTypeCount = 0;
        while (it2.hasNext()) {
            viewTypeCount += ((b) it2.next()).a.getViewTypeCount();
        }
        return Math.max(viewTypeCount, 1);
    }

    @Override // android.widget.BaseAdapter, android.widget.ListAdapter
    public final boolean isEnabled(int i) {
        Iterator it2 = c().iterator();
        while (it2.hasNext()) {
            ListAdapter listAdapter = (ListAdapter) it2.next();
            int count = listAdapter.getCount();
            if (i < count) {
                return listAdapter.isEnabled(i);
            }
            i -= count;
        }
        return false;
    }
}
