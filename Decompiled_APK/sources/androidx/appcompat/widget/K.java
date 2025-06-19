package androidx.appcompat.widget;

import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.widget.ListAdapter;
import androidx.appcompat.app.AlertController$RecycleListView;
import androidx.appcompat.app.C0047c;
import androidx.appcompat.app.C0051g;
import androidx.appcompat.app.DialogInterfaceC0052h;

/* loaded from: classes.dex */
public final class K implements Q, DialogInterface.OnClickListener {
    public DialogInterfaceC0052h a;
    public L b;
    public CharSequence c;
    public final /* synthetic */ AppCompatSpinner d;

    public K(AppCompatSpinner appCompatSpinner) {
        this.d = appCompatSpinner;
    }

    @Override // androidx.appcompat.widget.Q
    public final boolean a() {
        DialogInterfaceC0052h dialogInterfaceC0052h = this.a;
        if (dialogInterfaceC0052h != null) {
            return dialogInterfaceC0052h.isShowing();
        }
        return false;
    }

    @Override // androidx.appcompat.widget.Q
    public final int b() {
        return 0;
    }

    @Override // androidx.appcompat.widget.Q
    public final void d(int i) {
        Log.e("AppCompatSpinner", "Cannot set horizontal offset for MODE_DIALOG, ignoring");
    }

    @Override // androidx.appcompat.widget.Q
    public final void dismiss() {
        DialogInterfaceC0052h dialogInterfaceC0052h = this.a;
        if (dialogInterfaceC0052h != null) {
            dialogInterfaceC0052h.dismiss();
            this.a = null;
        }
    }

    @Override // androidx.appcompat.widget.Q
    public final CharSequence e() {
        return this.c;
    }

    @Override // androidx.appcompat.widget.Q
    public final Drawable g() {
        return null;
    }

    @Override // androidx.appcompat.widget.Q
    public final void h(CharSequence charSequence) {
        this.c = charSequence;
    }

    @Override // androidx.appcompat.widget.Q
    public final void j(Drawable drawable) {
        Log.e("AppCompatSpinner", "Cannot set popup background for MODE_DIALOG, ignoring");
    }

    @Override // androidx.appcompat.widget.Q
    public final void k(int i) {
        Log.e("AppCompatSpinner", "Cannot set vertical offset for MODE_DIALOG, ignoring");
    }

    @Override // androidx.appcompat.widget.Q
    public final void l(int i) {
        Log.e("AppCompatSpinner", "Cannot set horizontal (original) offset for MODE_DIALOG, ignoring");
    }

    @Override // androidx.appcompat.widget.Q
    public final void m(int i, int i2) {
        if (this.b == null) {
            return;
        }
        AppCompatSpinner appCompatSpinner = this.d;
        C0051g c0051g = new C0051g(appCompatSpinner.getPopupContext());
        CharSequence charSequence = this.c;
        if (charSequence != null) {
            c0051g.setTitle(charSequence);
        }
        L l = this.b;
        int selectedItemPosition = appCompatSpinner.getSelectedItemPosition();
        C0047c c0047c = c0051g.a;
        c0047c.m = l;
        c0047c.n = this;
        c0047c.q = selectedItemPosition;
        c0047c.p = true;
        DialogInterfaceC0052h dialogInterfaceC0052hCreate = c0051g.create();
        this.a = dialogInterfaceC0052hCreate;
        AlertController$RecycleListView alertController$RecycleListView = dialogInterfaceC0052hCreate.f.e;
        alertController$RecycleListView.setTextDirection(i);
        alertController$RecycleListView.setTextAlignment(i2);
        this.a.show();
    }

    @Override // androidx.appcompat.widget.Q
    public final int n() {
        return 0;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        AppCompatSpinner appCompatSpinner = this.d;
        appCompatSpinner.setSelection(i);
        if (appCompatSpinner.getOnItemClickListener() != null) {
            appCompatSpinner.performItemClick(null, i, this.b.getItemId(i));
        }
        dismiss();
    }

    @Override // androidx.appcompat.widget.Q
    public final void p(ListAdapter listAdapter) {
        this.b = (L) listAdapter;
    }
}
