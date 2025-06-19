package androidx.appcompat.app;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.PopupWindow;
import androidx.appcompat.view.WindowCallbackWrapper;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.ViewStubCompat;
import androidx.core.view.C1043d0;
import androidx.core.view.V;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class w extends WindowCallbackWrapper {
    public com.quizlet.data.repository.school.membership.a a;
    public boolean b;
    public boolean c;
    public boolean d;
    public final /* synthetic */ B e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(B b, Window.Callback callback) {
        super(callback);
        this.e = b;
    }

    public final void b(Window.Callback callback) {
        try {
            this.b = true;
            callback.onContentChanged();
        } finally {
            this.b = false;
        }
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return this.c ? a().dispatchKeyEvent(keyEvent) : this.e.u(keyEvent) || super.dispatchKeyEvent(keyEvent);
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final boolean dispatchKeyShortcutEvent(KeyEvent keyEvent) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        if (!super.dispatchKeyShortcutEvent(keyEvent)) {
            int keyCode = keyEvent.getKeyCode();
            B b = this.e;
            b.A();
            com.bumptech.glide.c cVar = b.o;
            if (cVar == null || !cVar.o(keyCode, keyEvent)) {
                A a = b.M;
                if (a == null || !b.G(a, keyEvent.getKeyCode(), keyEvent)) {
                    if (b.M == null) {
                        A aZ = b.z(0);
                        b.H(aZ, keyEvent);
                        boolean zG = b.G(aZ, keyEvent.getKeyCode(), keyEvent);
                        aZ.k = false;
                        if (zG) {
                        }
                    }
                    return false;
                }
                A a2 = b.M;
                if (a2 != null) {
                    a2.l = true;
                    return true;
                }
            }
        }
        return true;
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final void onContentChanged() {
        if (this.b) {
            a().onContentChanged();
        }
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final boolean onCreatePanelMenu(int i, Menu menu) {
        if (i != 0 || (menu instanceof androidx.appcompat.view.menu.n)) {
            return super.onCreatePanelMenu(i, menu);
        }
        return false;
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final View onCreatePanelView(int i) {
        com.quizlet.data.repository.school.membership.a aVar = this.a;
        if (aVar != null) {
            View view = i == 0 ? new View(((M) aVar.b).a.a.getContext()) : null;
            if (view != null) {
                return view;
            }
        }
        return super.onCreatePanelView(i);
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final boolean onMenuOpened(int i, Menu menu) {
        super.onMenuOpened(i, menu);
        B b = this.e;
        if (i == 108) {
            b.A();
            com.bumptech.glide.c cVar = b.o;
            if (cVar != null) {
                cVar.h(true);
            }
        } else {
            b.getClass();
        }
        return true;
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final void onPanelClosed(int i, Menu menu) {
        if (this.d) {
            a().onPanelClosed(i, menu);
            return;
        }
        super.onPanelClosed(i, menu);
        B b = this.e;
        if (i == 108) {
            b.A();
            com.bumptech.glide.c cVar = b.o;
            if (cVar != null) {
                cVar.h(false);
                return;
            }
            return;
        }
        if (i != 0) {
            b.getClass();
            return;
        }
        A aZ = b.z(i);
        if (aZ.m) {
            b.s(aZ, false);
        }
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final boolean onPreparePanel(int i, View view, Menu menu) {
        androidx.appcompat.view.menu.n nVar = menu instanceof androidx.appcompat.view.menu.n ? (androidx.appcompat.view.menu.n) menu : null;
        if (i == 0 && nVar == null) {
            return false;
        }
        if (nVar != null) {
            nVar.x = true;
        }
        com.quizlet.data.repository.school.membership.a aVar = this.a;
        if (aVar != null && i == 0) {
            M m = (M) aVar.b;
            if (!m.d) {
                m.a.l = true;
                m.d = true;
            }
        }
        boolean zOnPreparePanel = super.onPreparePanel(i, view, menu);
        if (nVar != null) {
            nVar.x = false;
        }
        return zOnPreparePanel;
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final void onProvideKeyboardShortcuts(List list, Menu menu, int i) {
        androidx.appcompat.view.menu.n nVar = this.e.z(0).h;
        if (nVar != null) {
            super.onProvideKeyboardShortcuts(list, nVar, i);
        } else {
            super.onProvideKeyboardShortcuts(list, menu, i);
        }
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final ActionMode onWindowStartingActionMode(ActionMode.Callback callback) {
        return null;
    }

    @Override // androidx.appcompat.view.WindowCallbackWrapper, android.view.Window.Callback
    public final ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int i) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        ViewGroup viewGroup;
        int i2 = 1;
        B b = this.e;
        b.getClass();
        if (i != 0) {
            return super.onWindowStartingActionMode(callback, i);
        }
        androidx.work.impl.model.i iVar = new androidx.work.impl.model.i(b.k, callback);
        androidx.appcompat.view.b bVar = b.u;
        if (bVar != null) {
            bVar.a();
        }
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(i2, b, iVar);
        b.A();
        com.bumptech.glide.c cVar = b.o;
        if (cVar != null) {
            b.u = cVar.E(uVar);
        }
        if (b.u == null) {
            C1043d0 c1043d0 = b.y;
            if (c1043d0 != null) {
                c1043d0.b();
            }
            androidx.appcompat.view.b bVar2 = b.u;
            if (bVar2 != null) {
                bVar2.a();
            }
            if (b.v == null) {
                boolean z = b.I;
                Context context = b.k;
                if (z) {
                    TypedValue typedValue = new TypedValue();
                    Resources.Theme theme = context.getTheme();
                    theme.resolveAttribute(R.attr.actionBarTheme, typedValue, true);
                    if (typedValue.resourceId != 0) {
                        Resources.Theme themeNewTheme = context.getResources().newTheme();
                        themeNewTheme.setTo(theme);
                        themeNewTheme.applyStyle(typedValue.resourceId, true);
                        androidx.appcompat.view.d dVar = new androidx.appcompat.view.d(context, 0);
                        dVar.getTheme().setTo(themeNewTheme);
                        context = dVar;
                    }
                    b.v = new ActionBarContextView(context);
                    PopupWindow popupWindow = new PopupWindow(context, (AttributeSet) null, R.attr.actionModePopupWindowStyle);
                    b.w = popupWindow;
                    popupWindow.setWindowLayoutType(2);
                    b.w.setContentView(b.v);
                    b.w.setWidth(-1);
                    context.getTheme().resolveAttribute(R.attr.actionBarSize, typedValue, true);
                    b.v.setContentHeight(TypedValue.complexToDimensionPixelSize(typedValue.data, context.getResources().getDisplayMetrics()));
                    b.w.setHeight(-2);
                    b.x = new r(b, i2);
                } else {
                    ViewStubCompat viewStubCompat = (ViewStubCompat) b.A.findViewById(R.id.action_mode_bar_stub);
                    if (viewStubCompat != null) {
                        b.A();
                        com.bumptech.glide.c cVar2 = b.o;
                        Context contextJ = cVar2 != null ? cVar2.j() : null;
                        if (contextJ != null) {
                            context = contextJ;
                        }
                        viewStubCompat.setLayoutInflater(LayoutInflater.from(context));
                        b.v = (ActionBarContextView) viewStubCompat.a();
                    }
                }
            }
            if (b.v != null) {
                C1043d0 c1043d02 = b.y;
                if (c1043d02 != null) {
                    c1043d02.b();
                }
                b.v.e();
                Context context2 = b.v.getContext();
                ActionBarContextView actionBarContextView = b.v;
                androidx.appcompat.view.e eVar = new androidx.appcompat.view.e();
                eVar.c = context2;
                eVar.d = actionBarContextView;
                eVar.e = uVar;
                androidx.appcompat.view.menu.n nVar = new androidx.appcompat.view.menu.n(actionBarContextView.getContext());
                nVar.l = 1;
                eVar.h = nVar;
                nVar.e = eVar;
                if (((androidx.work.impl.model.i) uVar.b).i(eVar, nVar)) {
                    eVar.g();
                    b.v.c(eVar);
                    b.u = eVar;
                    if (b.z && (viewGroup = b.A) != null && viewGroup.isLaidOut()) {
                        b.v.setAlpha(DefinitionKt.NO_Float_VALUE);
                        C1043d0 c1043d0A = V.a(b.v);
                        c1043d0A.a(1.0f);
                        b.y = c1043d0A;
                        c1043d0A.d(new C0062s(b, i2));
                    } else {
                        b.v.setAlpha(1.0f);
                        b.v.setVisibility(0);
                        if (b.v.getParent() instanceof View) {
                            View view = (View) b.v.getParent();
                            WeakHashMap weakHashMap = V.a;
                            androidx.core.view.J.c(view);
                        }
                    }
                    if (b.w != null) {
                        b.l.getDecorView().post(b.x);
                    }
                } else {
                    b.u = null;
                }
            }
            b.J();
            b.u = b.u;
        }
        b.J();
        androidx.appcompat.view.b bVar3 = b.u;
        if (bVar3 != null) {
            return iVar.b(bVar3);
        }
        return null;
    }
}
