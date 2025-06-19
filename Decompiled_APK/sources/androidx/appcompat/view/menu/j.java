package androidx.appcompat.view.menu;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.AdapterView;
import androidx.appcompat.app.C0047c;
import androidx.appcompat.app.C0051g;
import androidx.appcompat.app.DialogInterfaceC0052h;

/* loaded from: classes.dex */
public final class j implements z, AdapterView.OnItemClickListener {
    public Context a;
    public LayoutInflater b;
    public n c;
    public ExpandedMenuView d;
    public y e;
    public i f;

    public j(Context context) {
        this.a = context;
        this.b = LayoutInflater.from(context);
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean b() {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void c(y yVar) {
        throw null;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean d(p pVar) {
        return false;
    }

    @Override // androidx.appcompat.view.menu.z
    public final void e(n nVar, boolean z) {
        y yVar = this.e;
        if (yVar != null) {
            yVar.e(nVar, z);
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final void g(Context context, n nVar) {
        if (this.a != null) {
            this.a = context;
            if (this.b == null) {
                this.b = LayoutInflater.from(context);
            }
        }
        this.c = nVar;
        i iVar = this.f;
        if (iVar != null) {
            iVar.notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final void h() {
        i iVar = this.f;
        if (iVar != null) {
            iVar.notifyDataSetChanged();
        }
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean j(F f) {
        if (!f.hasVisibleItems()) {
            return false;
        }
        o oVar = new o();
        oVar.a = f;
        Context context = f.a;
        C0051g c0051g = new C0051g(context);
        j jVar = new j(c0051g.getContext());
        oVar.c = jVar;
        jVar.e = oVar;
        f.b(jVar, context);
        j jVar2 = oVar.c;
        if (jVar2.f == null) {
            jVar2.f = new i(jVar2);
        }
        i iVar = jVar2.f;
        C0047c c0047c = c0051g.a;
        c0047c.m = iVar;
        c0047c.n = oVar;
        View view = f.o;
        if (view != null) {
            c0047c.e = view;
        } else {
            c0047c.c = f.n;
            c0051g.setTitle(f.m);
        }
        c0047c.l = oVar;
        DialogInterfaceC0052h dialogInterfaceC0052hCreate = c0051g.create();
        oVar.b = dialogInterfaceC0052hCreate;
        dialogInterfaceC0052hCreate.setOnDismissListener(oVar);
        WindowManager.LayoutParams attributes = oVar.b.getWindow().getAttributes();
        attributes.type = 1003;
        attributes.flags |= 131072;
        oVar.b.show();
        y yVar = this.e;
        if (yVar == null) {
            return true;
        }
        yVar.z(f);
        return true;
    }

    @Override // androidx.appcompat.view.menu.z
    public final boolean k(p pVar) {
        return false;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        this.c.q(this.f.getItem(i), this, 0);
    }
}
