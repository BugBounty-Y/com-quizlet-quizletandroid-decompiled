package androidx.appcompat.widget;

import android.content.Intent;
import android.view.View;
import android.widget.AdapterView;
import com.google.android.gms.internal.oss_licenses.zze;
import com.google.android.gms.oss.licenses.OssLicensesActivity;
import com.google.android.gms.oss.licenses.OssLicensesMenuActivity;

/* loaded from: classes.dex */
public final class M implements AdapterView.OnItemClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ M(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        Object item;
        switch (this.a) {
            case 0:
                O o = (O) this.b;
                o.G.setSelection(i);
                AppCompatSpinner appCompatSpinner = o.G;
                if (appCompatSpinner.getOnItemClickListener() != null) {
                    appCompatSpinner.performItemClick(view, i, o.D.getItemId(i));
                }
                o.dismiss();
                break;
            case 1:
                ((SearchView) this.b).p(i);
                break;
            case 2:
                zze zzeVar = (zze) adapterView.getItemAtPosition(i);
                com.google.android.gms.internal.instantapps.a aVar = (com.google.android.gms.internal.instantapps.a) this.b;
                Intent intent = new Intent((OssLicensesMenuActivity) aVar.b, (Class<?>) OssLicensesActivity.class);
                intent.putExtra("license", zzeVar);
                ((OssLicensesMenuActivity) aVar.b).startActivity(intent);
                break;
            default:
                com.google.android.material.textfield.r rVar = (com.google.android.material.textfield.r) this.b;
                if (i < 0) {
                    G0 g0 = rVar.e;
                    item = !g0.z.isShowing() ? null : g0.c.getSelectedItem();
                } else {
                    item = rVar.getAdapter().getItem(i);
                }
                com.google.android.material.textfield.r.a(rVar, item);
                AdapterView.OnItemClickListener onItemClickListener = rVar.getOnItemClickListener();
                G0 g02 = rVar.e;
                if (onItemClickListener != null) {
                    if (view == null || i < 0) {
                        view = g02.z.isShowing() ? g02.c.getSelectedView() : null;
                        i = !g02.z.isShowing() ? -1 : g02.c.getSelectedItemPosition();
                        j = !g02.z.isShowing() ? Long.MIN_VALUE : g02.c.getSelectedItemId();
                    }
                    onItemClickListener.onItemClick(g02.c, view, i, j);
                }
                g02.dismiss();
                break;
        }
    }
}
