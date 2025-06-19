package com.google.android.gms.internal.mlkit_vision_barcode;

import android.app.ActionBar;
import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Build;
import android.util.SparseArray;
import android.view.KeyEvent;
import android.view.View;
import android.view.Window;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.core.view.InterfaceC1055l;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.r6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3250r6 {
    public static boolean a = false;
    public static Method b = null;
    public static boolean c = false;
    public static Field d;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onContinueClick) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(onContinueClick, "onContinueClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1183609830);
        int i2 = i | (c0814p.h(onContinueClick) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            mVar.q();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(nVar, com.quizlet.ui.resources.designsystem.generated.j.i, f);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0380d c0380d = AbstractC0398m.a;
            mVar.p();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f), gVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            qVar2 = nVar;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.qincentives_free_trial_confirmation), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).e, c0814p, 0, 0, 65018);
            c0814p = c0814p;
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(AbstractC3106b5.d(c0814p, R.string.qincentives_free_trial_continue_studying), androidx.compose.foundation.layout.K0.c(qVar2, 1.0f), onContinueClick, false, null, null, null, null, null, false, c0814p, ((i2 << 6) & 896) | 48, 1016);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(onContinueClick, qVar2, i, 7);
        }
    }

    public static boolean b(View view, KeyEvent keyEvent) {
        ArrayList arrayList;
        int size;
        int iIndexOfKey;
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        if (Build.VERSION.SDK_INT >= 28) {
            return false;
        }
        ArrayList arrayList2 = androidx.core.view.U.d;
        androidx.core.view.U u = (androidx.core.view.U) view.getTag(R.id.tag_unhandled_key_event_manager);
        WeakReference weakReference = null;
        if (u == null) {
            u = new androidx.core.view.U();
            u.a = null;
            u.b = null;
            u.c = null;
            view.setTag(R.id.tag_unhandled_key_event_manager, u);
        }
        WeakReference weakReference2 = u.c;
        if (weakReference2 != null && weakReference2.get() == keyEvent) {
            return false;
        }
        u.c = new WeakReference(keyEvent);
        if (u.b == null) {
            u.b = new SparseArray();
        }
        SparseArray sparseArray = u.b;
        if (keyEvent.getAction() == 1 && (iIndexOfKey = sparseArray.indexOfKey(keyEvent.getKeyCode())) >= 0) {
            weakReference = (WeakReference) sparseArray.valueAt(iIndexOfKey);
            sparseArray.removeAt(iIndexOfKey);
        }
        if (weakReference == null) {
            weakReference = (WeakReference) sparseArray.get(keyEvent.getKeyCode());
        }
        if (weakReference == null) {
            return false;
        }
        View view2 = (View) weakReference.get();
        if (view2 == null || !view2.isAttachedToWindow() || (arrayList = (ArrayList) view2.getTag(R.id.tag_unhandled_key_listeners)) == null || (size = arrayList.size() - 1) < 0) {
            return true;
        }
        arrayList.get(size).getClass();
        throw new ClassCastException();
    }

    public static boolean c(InterfaceC1055l interfaceC1055l, View view, Window.Callback callback, KeyEvent keyEvent) throws IllegalAccessException, NoSuchFieldException, SecurityException, IllegalArgumentException, InvocationTargetException {
        DialogInterface.OnKeyListener onKeyListener;
        boolean zBooleanValue = false;
        if (interfaceC1055l != null) {
            if (Build.VERSION.SDK_INT >= 28) {
                return interfaceC1055l.superDispatchKeyEvent(keyEvent);
            }
            if (callback instanceof Activity) {
                Activity activity = (Activity) callback;
                activity.onUserInteraction();
                Window window = activity.getWindow();
                if (window.hasFeature(8)) {
                    ActionBar actionBar = activity.getActionBar();
                    if (keyEvent.getKeyCode() == 82 && actionBar != null) {
                        if (!a) {
                            try {
                                b = actionBar.getClass().getMethod("onMenuKeyEvent", KeyEvent.class);
                            } catch (NoSuchMethodException unused) {
                            }
                            a = true;
                        }
                        Method method = b;
                        if (method != null) {
                            try {
                                Object objInvoke = method.invoke(actionBar, keyEvent);
                                if (objInvoke != null) {
                                    zBooleanValue = ((Boolean) objInvoke).booleanValue();
                                }
                            } catch (IllegalAccessException | InvocationTargetException unused2) {
                            }
                        }
                        if (zBooleanValue) {
                            return true;
                        }
                    }
                }
                if (window.superDispatchKeyEvent(keyEvent)) {
                    return true;
                }
                View decorView = window.getDecorView();
                if (androidx.core.view.V.c(decorView, keyEvent)) {
                    return true;
                }
                return keyEvent.dispatch(activity, decorView != null ? decorView.getKeyDispatcherState() : null, activity);
            }
            if (callback instanceof Dialog) {
                Dialog dialog = (Dialog) callback;
                if (!c) {
                    try {
                        Field declaredField = Dialog.class.getDeclaredField("mOnKeyListener");
                        d = declaredField;
                        declaredField.setAccessible(true);
                    } catch (NoSuchFieldException unused3) {
                    }
                    c = true;
                }
                Field field = d;
                if (field != null) {
                    try {
                        onKeyListener = (DialogInterface.OnKeyListener) field.get(dialog);
                    } catch (IllegalAccessException unused4) {
                    }
                } else {
                    onKeyListener = null;
                }
                if (onKeyListener != null && onKeyListener.onKey(dialog, keyEvent.getKeyCode(), keyEvent)) {
                    return true;
                }
                Window window2 = dialog.getWindow();
                if (window2.superDispatchKeyEvent(keyEvent)) {
                    return true;
                }
                View decorView2 = window2.getDecorView();
                if (androidx.core.view.V.c(decorView2, keyEvent)) {
                    return true;
                }
                return keyEvent.dispatch(dialog, decorView2 != null ? decorView2.getKeyDispatcherState() : null, dialog);
            }
            if ((view != null && androidx.core.view.V.c(view, keyEvent)) || interfaceC1055l.superDispatchKeyEvent(keyEvent)) {
                return true;
            }
        }
        return false;
    }

    public static final String d(EnumC4159q0 enumC4159q0, InterfaceC0806l interfaceC0806l) {
        String strH;
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(enumC4159q0, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1266592648);
        int iOrdinal = enumC4159q0.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                i = 1619434260;
                i2 = R.string.new_tag_error_message;
            } else if (iOrdinal == 2) {
                i = 1619436966;
                i2 = R.string.new_tag_already_in_folder_error_message;
            } else {
                if (iOrdinal != 3) {
                    throw com.google.android.gms.measurement.internal.Z.j(1619432067, c0814p, false);
                }
                i = 1619440280;
                i2 = R.string.tag_limit_reached_message;
            }
            strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        } else {
            c0814p.X(-1337182505);
            c0814p.p(false);
            strH = null;
        }
        c0814p.p(false);
        return strH;
    }
}
