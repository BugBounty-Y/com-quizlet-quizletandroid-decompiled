package androidx.appcompat.app;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.TextView;
import androidx.appcompat.widget.C0121y0;
import androidx.core.view.V;
import androidx.core.widget.NestedScrollView;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* renamed from: androidx.appcompat.app.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class DialogInterfaceC0052h extends D implements DialogInterface {
    public final C0050f f;

    public DialogInterfaceC0052h(Context context, int i) {
        super(context, f(context, i));
        this.f = new C0050f(getContext(), this, getWindow());
    }

    public static int f(Context context, int i) {
        if (((i >>> 24) & 255) >= 1) {
            return i;
        }
        TypedValue typedValue = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.alertDialogTheme, typedValue, true);
        return typedValue.resourceId;
    }

    @Override // androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public final void onCreate(Bundle bundle) {
        int i;
        int i2;
        int i3;
        ListAdapter listAdapter;
        View viewFindViewById;
        super.onCreate(bundle);
        C0050f c0050f = this.f;
        c0050f.b.setContentView(c0050f.y);
        Window window = c0050f.c;
        View viewFindViewById2 = window.findViewById(R.id.parentPanel);
        View viewFindViewById3 = viewFindViewById2.findViewById(R.id.topPanel);
        View viewFindViewById4 = viewFindViewById2.findViewById(R.id.contentPanel);
        View viewFindViewById5 = viewFindViewById2.findViewById(R.id.buttonPanel);
        ViewGroup viewGroup = (ViewGroup) viewFindViewById2.findViewById(R.id.customPanel);
        View view = c0050f.f;
        if (view == null) {
            view = null;
        }
        boolean z = view != null;
        if (!z || !C0050f.a(view)) {
            window.setFlags(131072, 131072);
        }
        if (z) {
            i = 2;
            FrameLayout frameLayout = (FrameLayout) window.findViewById(R.id.custom);
            frameLayout.addView(view, new ViewGroup.LayoutParams(-1, -1));
            if (c0050f.g) {
                frameLayout.setPadding(0, 0, 0, 0);
            }
            if (c0050f.e != null) {
                ((LinearLayout.LayoutParams) ((C0121y0) viewGroup.getLayoutParams())).weight = DefinitionKt.NO_Float_VALUE;
            }
        } else {
            i = 2;
            viewGroup.setVisibility(8);
        }
        View viewFindViewById6 = viewGroup.findViewById(R.id.topPanel);
        View viewFindViewById7 = viewGroup.findViewById(R.id.contentPanel);
        View viewFindViewById8 = viewGroup.findViewById(R.id.buttonPanel);
        ViewGroup viewGroupB = C0050f.b(viewFindViewById6, viewFindViewById3);
        ViewGroup viewGroupB2 = C0050f.b(viewFindViewById7, viewFindViewById4);
        ViewGroup viewGroupB3 = C0050f.b(viewFindViewById8, viewFindViewById5);
        NestedScrollView nestedScrollView = (NestedScrollView) window.findViewById(R.id.scrollView);
        c0050f.q = nestedScrollView;
        nestedScrollView.setFocusable(false);
        c0050f.q.setNestedScrollingEnabled(false);
        TextView textView = (TextView) viewGroupB2.findViewById(android.R.id.message);
        c0050f.u = textView;
        if (textView != null) {
            textView.setVisibility(8);
            c0050f.q.removeView(c0050f.u);
            if (c0050f.e != null) {
                ViewGroup viewGroup2 = (ViewGroup) c0050f.q.getParent();
                int iIndexOfChild = viewGroup2.indexOfChild(c0050f.q);
                viewGroup2.removeViewAt(iIndexOfChild);
                viewGroup2.addView(c0050f.e, iIndexOfChild, new ViewGroup.LayoutParams(-1, -1));
            } else {
                viewGroupB2.setVisibility(8);
            }
        }
        Button button = (Button) viewGroupB3.findViewById(android.R.id.button1);
        c0050f.h = button;
        ViewOnClickListenerC0045a viewOnClickListenerC0045a = c0050f.E;
        button.setOnClickListener(viewOnClickListenerC0045a);
        if (TextUtils.isEmpty(c0050f.i)) {
            c0050f.h.setVisibility(8);
            i2 = 0;
        } else {
            c0050f.h.setText(c0050f.i);
            c0050f.h.setVisibility(0);
            i2 = 1;
        }
        Button button2 = (Button) viewGroupB3.findViewById(android.R.id.button2);
        c0050f.k = button2;
        button2.setOnClickListener(viewOnClickListenerC0045a);
        if (TextUtils.isEmpty(c0050f.l)) {
            c0050f.k.setVisibility(8);
        } else {
            c0050f.k.setText(c0050f.l);
            c0050f.k.setVisibility(0);
            i2 |= 2;
        }
        Button button3 = (Button) viewGroupB3.findViewById(android.R.id.button3);
        c0050f.n = button3;
        button3.setOnClickListener(viewOnClickListenerC0045a);
        if (TextUtils.isEmpty(c0050f.o)) {
            c0050f.n.setVisibility(8);
        } else {
            c0050f.n.setText(c0050f.o);
            c0050f.n.setVisibility(0);
            i2 |= 4;
        }
        TypedValue typedValue = new TypedValue();
        c0050f.a.getTheme().resolveAttribute(R.attr.alertDialogCenterButtons, typedValue, true);
        if (typedValue.data == 0) {
            i3 = i;
        } else if (i2 == 1) {
            Button button4 = c0050f.h;
            LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) button4.getLayoutParams();
            layoutParams.gravity = 1;
            layoutParams.weight = 0.5f;
            button4.setLayoutParams(layoutParams);
            i3 = i;
        } else {
            i3 = i;
            if (i2 == i3) {
                Button button5 = c0050f.k;
                LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) button5.getLayoutParams();
                layoutParams2.gravity = 1;
                layoutParams2.weight = 0.5f;
                button5.setLayoutParams(layoutParams2);
            } else if (i2 == 4) {
                Button button6 = c0050f.n;
                LinearLayout.LayoutParams layoutParams3 = (LinearLayout.LayoutParams) button6.getLayoutParams();
                layoutParams3.gravity = 1;
                layoutParams3.weight = 0.5f;
                button6.setLayoutParams(layoutParams3);
            }
        }
        if (i2 == 0) {
            viewGroupB3.setVisibility(8);
        }
        if (c0050f.v != null) {
            viewGroupB.addView(c0050f.v, 0, new ViewGroup.LayoutParams(-1, -2));
            window.findViewById(R.id.title_template).setVisibility(8);
        } else {
            c0050f.s = (ImageView) window.findViewById(android.R.id.icon);
            if (TextUtils.isEmpty(c0050f.d) || !c0050f.C) {
                window.findViewById(R.id.title_template).setVisibility(8);
                c0050f.s.setVisibility(8);
                viewGroupB.setVisibility(8);
            } else {
                TextView textView2 = (TextView) window.findViewById(R.id.alertTitle);
                c0050f.t = textView2;
                textView2.setText(c0050f.d);
                Drawable drawable = c0050f.r;
                if (drawable != null) {
                    c0050f.s.setImageDrawable(drawable);
                } else {
                    c0050f.t.setPadding(c0050f.s.getPaddingLeft(), c0050f.s.getPaddingTop(), c0050f.s.getPaddingRight(), c0050f.s.getPaddingBottom());
                    c0050f.s.setVisibility(8);
                }
            }
        }
        boolean z2 = viewGroup.getVisibility() != 8;
        int i4 = (viewGroupB == null || viewGroupB.getVisibility() == 8) ? 0 : 1;
        boolean z3 = viewGroupB3.getVisibility() != 8;
        if (!z3 && (viewFindViewById = viewGroupB2.findViewById(R.id.textSpacerNoButtons)) != null) {
            viewFindViewById.setVisibility(0);
        }
        if (i4 != 0) {
            NestedScrollView nestedScrollView2 = c0050f.q;
            if (nestedScrollView2 != null) {
                nestedScrollView2.setClipToPadding(true);
            }
            View viewFindViewById9 = c0050f.e != null ? viewGroupB.findViewById(R.id.titleDividerNoCustom) : null;
            if (viewFindViewById9 != null) {
                viewFindViewById9.setVisibility(0);
            }
        } else {
            View viewFindViewById10 = viewGroupB2.findViewById(R.id.textSpacerNoTitle);
            if (viewFindViewById10 != null) {
                viewFindViewById10.setVisibility(0);
            }
        }
        AlertController$RecycleListView alertController$RecycleListView = c0050f.e;
        if (alertController$RecycleListView != null && (!z3 || i4 == 0)) {
            alertController$RecycleListView.setPadding(alertController$RecycleListView.getPaddingLeft(), i4 != 0 ? alertController$RecycleListView.getPaddingTop() : alertController$RecycleListView.a, alertController$RecycleListView.getPaddingRight(), z3 ? alertController$RecycleListView.getPaddingBottom() : alertController$RecycleListView.b);
        }
        if (!z2) {
            View view2 = c0050f.e;
            if (view2 == null) {
                view2 = c0050f.q;
            }
            if (view2 != null) {
                int i5 = i4 | (z3 ? i3 : 0);
                View viewFindViewById11 = window.findViewById(R.id.scrollIndicatorUp);
                View viewFindViewById12 = window.findViewById(R.id.scrollIndicatorDown);
                WeakHashMap weakHashMap = V.a;
                androidx.core.view.M.b(view2, i5, 3);
                if (viewFindViewById11 != null) {
                    viewGroupB2.removeView(viewFindViewById11);
                }
                if (viewFindViewById12 != null) {
                    viewGroupB2.removeView(viewFindViewById12);
                }
            }
        }
        AlertController$RecycleListView alertController$RecycleListView2 = c0050f.e;
        if (alertController$RecycleListView2 == null || (listAdapter = c0050f.w) == null) {
            return;
        }
        alertController$RecycleListView2.setAdapter(listAdapter);
        int i6 = c0050f.x;
        if (i6 > -1) {
            alertController$RecycleListView2.setItemChecked(i6, true);
            alertController$RecycleListView2.setSelection(i6);
        }
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public final boolean onKeyDown(int i, KeyEvent keyEvent) {
        NestedScrollView nestedScrollView = this.f.q;
        if (nestedScrollView == null || !nestedScrollView.j(keyEvent)) {
            return super.onKeyDown(i, keyEvent);
        }
        return true;
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public final boolean onKeyUp(int i, KeyEvent keyEvent) {
        NestedScrollView nestedScrollView = this.f.q;
        if (nestedScrollView == null || !nestedScrollView.j(keyEvent)) {
            return super.onKeyUp(i, keyEvent);
        }
        return true;
    }

    @Override // androidx.appcompat.app.D, android.app.Dialog
    public final void setTitle(CharSequence charSequence) {
        super.setTitle(charSequence);
        C0050f c0050f = this.f;
        c0050f.d = charSequence;
        TextView textView = c0050f.t;
        if (textView != null) {
            textView.setText(charSequence);
        }
    }
}
