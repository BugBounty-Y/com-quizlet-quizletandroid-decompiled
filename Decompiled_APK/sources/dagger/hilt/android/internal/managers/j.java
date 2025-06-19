package dagger.hilt.android.internal.managers;

import android.content.Context;
import android.content.ContextWrapper;
import android.view.LayoutInflater;
import androidx.fragment.app.Fragment;

/* loaded from: classes3.dex */
public final class j extends ContextWrapper {
    public LayoutInflater a;
    public LayoutInflater b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(Context context, Fragment fragment) {
        super(context);
        context.getClass();
        androidx.savedstate.a aVar = new androidx.savedstate.a(this, 2);
        this.a = null;
        fragment.getClass();
        fragment.getLifecycle().a(aVar);
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public final Object getSystemService(String str) {
        if (!"layout_inflater".equals(str)) {
            return getBaseContext().getSystemService(str);
        }
        if (this.b == null) {
            if (this.a == null) {
                this.a = (LayoutInflater) getBaseContext().getSystemService("layout_inflater");
            }
            this.b = this.a.cloneInContext(this);
        }
        return this.b;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public j(LayoutInflater layoutInflater, Fragment fragment) {
        layoutInflater.getClass();
        Context context = layoutInflater.getContext();
        context.getClass();
        super(context);
        androidx.savedstate.a aVar = new androidx.savedstate.a(this, 2);
        this.a = layoutInflater;
        fragment.getClass();
        fragment.getLifecycle().a(aVar);
    }
}
