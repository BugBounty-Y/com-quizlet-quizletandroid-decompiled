package androidx.appcompat.app;

import android.content.DialogInterface;
import android.view.View;
import android.widget.AdapterView;

/* renamed from: androidx.appcompat.app.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0046b implements AdapterView.OnItemClickListener {
    public final /* synthetic */ C0050f a;
    public final /* synthetic */ C0047c b;

    public C0046b(C0047c c0047c, C0050f c0050f) {
        this.b = c0047c;
        this.a = c0050f;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        C0047c c0047c = this.b;
        DialogInterface.OnClickListener onClickListener = c0047c.n;
        C0050f c0050f = this.a;
        onClickListener.onClick(c0050f.b, i);
        if (c0047c.p) {
            return;
        }
        c0050f.b.dismiss();
    }
}
