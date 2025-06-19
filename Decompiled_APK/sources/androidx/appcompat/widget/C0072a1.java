package androidx.appcompat.widget;

import android.view.KeyEvent;
import android.widget.TextView;

/* renamed from: androidx.appcompat.widget.a1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0072a1 implements TextView.OnEditorActionListener {
    public final /* synthetic */ SearchView a;

    public C0072a1(SearchView searchView) {
        this.a = searchView;
    }

    @Override // android.widget.TextView.OnEditorActionListener
    public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
        this.a.s();
        return true;
    }
}
