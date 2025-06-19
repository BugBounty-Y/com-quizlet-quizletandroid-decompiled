package androidx.appcompat.app;

import android.R;
import android.content.res.TypedArray;
import android.os.Message;
import android.util.SparseArray;
import android.view.View;
import android.widget.CheckedTextView;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.s1;
import com.google.android.exoplayer2.ui.TrackSelectionView;

/* renamed from: androidx.appcompat.app.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ViewOnClickListenerC0045a implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ ViewOnClickListenerC0045a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        Message message;
        Message message2;
        Message message3;
        switch (this.a) {
            case 0:
                C0050f c0050f = (C0050f) this.b;
                Message messageObtain = (view != c0050f.h || (message3 = c0050f.j) == null) ? (view != c0050f.k || (message2 = c0050f.m) == null) ? (view != c0050f.n || (message = c0050f.p) == null) ? null : Message.obtain(message) : Message.obtain(message2) : Message.obtain(message3);
                if (messageObtain != null) {
                    messageObtain.sendToTarget();
                }
                c0050f.D.obtainMessage(1, c0050f.b).sendToTarget();
                return;
            case 1:
                ((androidx.appcompat.view.b) this.b).a();
                return;
            case 2:
                s1 s1Var = ((Toolbar) this.b).M;
                androidx.appcompat.view.menu.p pVar = s1Var == null ? null : s1Var.b;
                if (pVar != null) {
                    pVar.collapseActionView();
                    return;
                }
                return;
            case 3:
                TrackSelectionView trackSelectionView = (TrackSelectionView) this.b;
                SparseArray sparseArray = trackSelectionView.c;
                boolean z = false;
                CheckedTextView checkedTextView = trackSelectionView.b;
                CheckedTextView checkedTextView2 = trackSelectionView.a;
                if (view == checkedTextView2) {
                    trackSelectionView.f = true;
                    sparseArray.clear();
                } else {
                    if (view != checkedTextView) {
                        trackSelectionView.f = false;
                        view.getTag().getClass();
                        throw new ClassCastException();
                    }
                    trackSelectionView.f = false;
                    sparseArray.clear();
                }
                checkedTextView2.setChecked(trackSelectionView.f);
                if (!trackSelectionView.f && sparseArray.size() == 0) {
                    z = true;
                }
                checkedTextView.setChecked(z);
                throw null;
            case 4:
                com.google.android.gms.ads.internal.overlay.d dVar = (com.google.android.gms.ads.internal.overlay.d) this.b;
                dVar.w = 2;
                dVar.b.finish();
                return;
            case 5:
                com.google.android.material.bottomsheet.h hVar = (com.google.android.material.bottomsheet.h) this.b;
                if (hVar.j && hVar.isShowing()) {
                    if (!hVar.l) {
                        TypedArray typedArrayObtainStyledAttributes = hVar.getContext().obtainStyledAttributes(new int[]{R.attr.windowCloseOnTouchOutside});
                        hVar.k = typedArrayObtainStyledAttributes.getBoolean(0, true);
                        typedArrayObtainStyledAttributes.recycle();
                        hVar.l = true;
                    }
                    if (hVar.k) {
                        hVar.cancel();
                        return;
                    }
                    return;
                }
                return;
            default:
                com.google.android.material.datepicker.k kVar = (com.google.android.material.datepicker.k) this.b;
                int i = kVar.e;
                if (i == 2) {
                    kVar.H(1);
                    return;
                } else {
                    if (i == 1) {
                        kVar.H(2);
                        return;
                    }
                    return;
                }
        }
    }
}
