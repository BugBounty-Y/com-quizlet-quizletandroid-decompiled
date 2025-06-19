package com.quizlet.features.infra.legacyadapter.helper;

import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuItem;
import com.quizlet.quizletandroid.ui.group.addclassset.c;
import java.lang.ref.WeakReference;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class a implements ActionMode.Callback {
    public ActionMode b;
    public final WeakReference c;
    public ArrayList a = new ArrayList();
    public final int d = -1;

    public a(c cVar) {
        this.c = new WeakReference(cVar);
    }

    public final void a(ActionMode actionMode) {
        this.b = actionMode;
        if (actionMode != null) {
            actionMode.setTitle(Integer.toString(this.a.size()));
        }
        WeakReference weakReference = this.c;
        if (actionMode == null) {
            this.a.clear();
            c cVar = (c) weakReference.get();
            if (cVar != null) {
                cVar.a.z.notifyDataSetChanged();
            }
        }
    }

    public final void b(long j) {
        if (this.a.contains(Long.valueOf(j))) {
            this.a.remove(Long.valueOf(j));
        } else {
            this.a.add(Long.valueOf(j));
        }
        if (this.b != null && this.a.size() <= 0) {
            this.b.finish();
        }
        ActionMode actionMode = this.b;
        if (actionMode != null) {
            actionMode.setTitle(Integer.toString(this.a.size()));
        }
        c cVar = (c) this.c.get();
        if (cVar != null) {
            cVar.a.z.notifyDataSetChanged();
        }
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onActionItemClicked(ActionMode actionMode, MenuItem menuItem) {
        return false;
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
        actionMode.getMenuInflater().inflate(this.d, menu);
        a(actionMode);
        for (int i = 0; i < menu.size(); i++) {
            MenuItem item = menu.getItem(i);
            if (item.getActionView() != null) {
                item.getActionView().setOnClickListener(new com.braze.ui.inappmessage.views.a(19, menu, item));
            }
        }
        return true;
    }

    @Override // android.view.ActionMode.Callback
    public final void onDestroyActionMode(ActionMode actionMode) {
        a(null);
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
        return true;
    }
}
