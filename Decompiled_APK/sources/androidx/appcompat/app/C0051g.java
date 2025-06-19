package androidx.appcompat.app;

import android.R;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.view.ContextThemeWrapper;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;

/* renamed from: androidx.appcompat.app.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0051g {
    public final C0047c a;
    public final int b;

    public C0051g(@NonNull Context context) {
        this(context, DialogInterfaceC0052h.f(context, 0));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v1, types: [android.widget.ListAdapter] */
    /* JADX WARN: Type inference failed for: r8v3 */
    /* JADX WARN: Type inference failed for: r8v4 */
    @NonNull
    public DialogInterfaceC0052h create() {
        C0047c c0047c = this.a;
        DialogInterfaceC0052h dialogInterfaceC0052h = new DialogInterfaceC0052h(c0047c.a, this.b);
        View view = c0047c.e;
        C0050f c0050f = dialogInterfaceC0052h.f;
        if (view != null) {
            c0050f.v = view;
        } else {
            CharSequence charSequence = c0047c.d;
            if (charSequence != null) {
                c0050f.d = charSequence;
                TextView textView = c0050f.t;
                if (textView != null) {
                    textView.setText(charSequence);
                }
            }
            Drawable drawable = c0047c.c;
            if (drawable != null) {
                c0050f.r = drawable;
                ImageView imageView = c0050f.s;
                if (imageView != null) {
                    imageView.setVisibility(0);
                    c0050f.s.setImageDrawable(drawable);
                }
            }
        }
        CharSequence charSequence2 = c0047c.f;
        if (charSequence2 != null) {
            c0050f.c(-1, charSequence2, c0047c.g);
        }
        CharSequence charSequence3 = c0047c.h;
        if (charSequence3 != null) {
            c0050f.c(-2, charSequence3, c0047c.i);
        }
        CharSequence charSequence4 = c0047c.j;
        if (charSequence4 != null) {
            c0050f.c(-3, charSequence4, c0047c.k);
        }
        Object[] objArr = null;
        if (c0047c.m != null) {
            AlertController$RecycleListView alertController$RecycleListView = (AlertController$RecycleListView) c0047c.b.inflate(c0050f.z, (ViewGroup) null);
            int i = c0047c.p ? c0050f.A : c0050f.B;
            Object obj = c0047c.m;
            ?? c0049e = obj;
            if (obj == null) {
                c0049e = new C0049e(c0047c.a, i, R.id.text1, objArr);
            }
            c0050f.w = c0049e;
            c0050f.x = c0047c.q;
            if (c0047c.n != null) {
                alertController$RecycleListView.setOnItemClickListener(new C0046b(c0047c, c0050f));
            }
            if (c0047c.p) {
                alertController$RecycleListView.setChoiceMode(1);
            }
            c0050f.e = alertController$RecycleListView;
        }
        View view2 = c0047c.o;
        if (view2 != null) {
            c0050f.f = view2;
            c0050f.g = false;
        }
        dialogInterfaceC0052h.setCancelable(true);
        dialogInterfaceC0052h.setCanceledOnTouchOutside(true);
        dialogInterfaceC0052h.setOnCancelListener(null);
        dialogInterfaceC0052h.setOnDismissListener(null);
        androidx.appcompat.view.menu.o oVar = c0047c.l;
        if (oVar != null) {
            dialogInterfaceC0052h.setOnKeyListener(oVar);
        }
        return dialogInterfaceC0052h;
    }

    @NonNull
    public Context getContext() {
        return this.a.a;
    }

    public C0051g setNegativeButton(int i, DialogInterface.OnClickListener onClickListener) {
        C0047c c0047c = this.a;
        c0047c.h = c0047c.a.getText(i);
        c0047c.i = onClickListener;
        return this;
    }

    public C0051g setPositiveButton(int i, DialogInterface.OnClickListener onClickListener) {
        C0047c c0047c = this.a;
        c0047c.f = c0047c.a.getText(i);
        c0047c.g = onClickListener;
        return this;
    }

    public C0051g setTitle(CharSequence charSequence) {
        this.a.d = charSequence;
        return this;
    }

    public C0051g setView(View view) {
        this.a.o = view;
        return this;
    }

    public C0051g(@NonNull Context context, int i) {
        this.a = new C0047c(new ContextThemeWrapper(context, DialogInterfaceC0052h.f(context, i)));
        this.b = i;
    }
}
