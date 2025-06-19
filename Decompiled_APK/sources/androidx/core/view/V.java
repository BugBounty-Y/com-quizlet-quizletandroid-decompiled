package androidx.core.view;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.TypedArray;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewParent;
import android.view.Window;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.animation.PathInterpolator;
import androidx.appcompat.widget.C0116w;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Objects;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public abstract class V {
    public static WeakHashMap a = null;
    public static Field b = null;
    public static boolean c = false;
    public static final int[] d = {R.id.accessibility_custom_action_0, R.id.accessibility_custom_action_1, R.id.accessibility_custom_action_2, R.id.accessibility_custom_action_3, R.id.accessibility_custom_action_4, R.id.accessibility_custom_action_5, R.id.accessibility_custom_action_6, R.id.accessibility_custom_action_7, R.id.accessibility_custom_action_8, R.id.accessibility_custom_action_9, R.id.accessibility_custom_action_10, R.id.accessibility_custom_action_11, R.id.accessibility_custom_action_12, R.id.accessibility_custom_action_13, R.id.accessibility_custom_action_14, R.id.accessibility_custom_action_15, R.id.accessibility_custom_action_16, R.id.accessibility_custom_action_17, R.id.accessibility_custom_action_18, R.id.accessibility_custom_action_19, R.id.accessibility_custom_action_20, R.id.accessibility_custom_action_21, R.id.accessibility_custom_action_22, R.id.accessibility_custom_action_23, R.id.accessibility_custom_action_24, R.id.accessibility_custom_action_25, R.id.accessibility_custom_action_26, R.id.accessibility_custom_action_27, R.id.accessibility_custom_action_28, R.id.accessibility_custom_action_29, R.id.accessibility_custom_action_30, R.id.accessibility_custom_action_31};
    public static final F e = new F();
    public static final H f = new H();

    public static C1043d0 a(View view) {
        if (a == null) {
            a = new WeakHashMap();
        }
        C1043d0 c1043d0 = (C1043d0) a.get(view);
        if (c1043d0 != null) {
            return c1043d0;
        }
        C1043d0 c1043d02 = new C1043d0(view);
        a.put(view, c1043d02);
        return c1043d02;
    }

    public static D0 b(D0 d0, View view) {
        int i = Build.VERSION.SDK_INT;
        WindowInsets windowInsetsG = d0.g();
        if (windowInsetsG == null) {
            return d0;
        }
        WindowInsets windowInsetsA = i >= 30 ? S.a(view, windowInsetsG) : J.a(view, windowInsetsG);
        return !windowInsetsA.equals(windowInsetsG) ? D0.h(view, windowInsetsA) : d0;
    }

    public static boolean c(View view, KeyEvent keyEvent) {
        if (Build.VERSION.SDK_INT >= 28) {
            return false;
        }
        ArrayList arrayList = U.d;
        U u = (U) view.getTag(R.id.tag_unhandled_key_event_manager);
        if (u == null) {
            u = new U();
            u.a = null;
            u.b = null;
            u.c = null;
            view.setTag(R.id.tag_unhandled_key_event_manager, u);
        }
        if (keyEvent.getAction() == 0) {
            WeakHashMap weakHashMap = u.a;
            if (weakHashMap != null) {
                weakHashMap.clear();
            }
            ArrayList arrayList2 = U.d;
            if (!arrayList2.isEmpty()) {
                synchronized (arrayList2) {
                    try {
                        if (u.a == null) {
                            u.a = new WeakHashMap();
                        }
                        for (int size = arrayList2.size() - 1; size >= 0; size--) {
                            ArrayList arrayList3 = U.d;
                            View view2 = (View) ((WeakReference) arrayList3.get(size)).get();
                            if (view2 == null) {
                                arrayList3.remove(size);
                            } else {
                                u.a.put(view2, Boolean.TRUE);
                                for (ViewParent parent = view2.getParent(); parent instanceof View; parent = parent.getParent()) {
                                    u.a.put((View) parent, Boolean.TRUE);
                                }
                            }
                        }
                    } finally {
                    }
                }
            }
        }
        View viewA = u.a(view);
        if (keyEvent.getAction() == 0) {
            int keyCode = keyEvent.getKeyCode();
            if (viewA != null && !KeyEvent.isModifierKey(keyCode)) {
                if (u.b == null) {
                    u.b = new SparseArray();
                }
                u.b.put(keyCode, new WeakReference(viewA));
            }
        }
        return viewA != null;
    }

    public static View.AccessibilityDelegate d(View view) {
        if (Build.VERSION.SDK_INT >= 29) {
            return Q.a(view);
        }
        if (c) {
            return null;
        }
        if (b == null) {
            try {
                Field declaredField = View.class.getDeclaredField("mAccessibilityDelegate");
                b = declaredField;
                declaredField.setAccessible(true);
            } catch (Throwable unused) {
                c = true;
                return null;
            }
        }
        try {
            Object obj = b.get(view);
            if (obj instanceof View.AccessibilityDelegate) {
                return (View.AccessibilityDelegate) obj;
            }
            return null;
        } catch (Throwable unused2) {
            c = true;
            return null;
        }
    }

    public static CharSequence e(View view) {
        Object tag;
        if (Build.VERSION.SDK_INT >= 28) {
            tag = P.a(view);
        } else {
            tag = view.getTag(R.id.tag_accessibility_pane_title);
            if (!CharSequence.class.isInstance(tag)) {
                tag = null;
            }
        }
        return (CharSequence) tag;
    }

    public static ArrayList f(View view) {
        ArrayList arrayList = (ArrayList) view.getTag(R.id.tag_accessibility_actions);
        if (arrayList != null) {
            return arrayList;
        }
        ArrayList arrayList2 = new ArrayList();
        view.setTag(R.id.tag_accessibility_actions, arrayList2);
        return arrayList2;
    }

    public static String[] g(C0116w c0116w) {
        return Build.VERSION.SDK_INT >= 31 ? T.a(c0116w) : (String[]) c0116w.getTag(R.id.tag_on_receive_content_mime_types);
    }

    public static H0 h(View view) {
        if (Build.VERSION.SDK_INT >= 30) {
            return S.c(view);
        }
        for (Context context = view.getContext(); context instanceof ContextWrapper; context = ((ContextWrapper) context).getBaseContext()) {
            if (context instanceof Activity) {
                Window window = ((Activity) context).getWindow();
                if (window != null) {
                    return new H0(window, view);
                }
                return null;
            }
        }
        return null;
    }

    public static void i(int i, View view) {
        AccessibilityManager accessibilityManager = (AccessibilityManager) view.getContext().getSystemService("accessibility");
        if (accessibilityManager.isEnabled()) {
            boolean z = e(view) != null && view.isShown() && view.getWindowVisibility() == 0;
            if (view.getAccessibilityLiveRegion() != 0 || z) {
                AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain();
                accessibilityEventObtain.setEventType(z ? 32 : 2048);
                accessibilityEventObtain.setContentChangeTypes(i);
                if (z) {
                    accessibilityEventObtain.getText().add(e(view));
                    if (view.getImportantForAccessibility() == 0) {
                        view.setImportantForAccessibility(1);
                    }
                }
                view.sendAccessibilityEventUnchecked(accessibilityEventObtain);
                return;
            }
            if (i != 32) {
                if (view.getParent() != null) {
                    try {
                        view.getParent().notifySubtreeAccessibilityStateChanged(view, view, i);
                        return;
                    } catch (AbstractMethodError e2) {
                        Log.e("ViewCompat", view.getParent().getClass().getSimpleName().concat(" does not fully implement ViewParent"), e2);
                        return;
                    }
                }
                return;
            }
            AccessibilityEvent accessibilityEventObtain2 = AccessibilityEvent.obtain();
            view.onInitializeAccessibilityEvent(accessibilityEventObtain2);
            accessibilityEventObtain2.setEventType(32);
            accessibilityEventObtain2.setContentChangeTypes(i);
            accessibilityEventObtain2.setSource(view);
            view.onPopulateAccessibilityEvent(accessibilityEventObtain2);
            accessibilityEventObtain2.getText().add(e(view));
            accessibilityManager.sendAccessibilityEvent(accessibilityEventObtain2);
        }
    }

    public static D0 j(D0 d0, View view) {
        WindowInsets windowInsetsG = d0.g();
        if (windowInsetsG == null) {
            return d0;
        }
        WindowInsets windowInsetsB = J.b(view, windowInsetsG);
        return !windowInsetsB.equals(windowInsetsG) ? D0.h(view, windowInsetsB) : d0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static C1050h k(View view, C1050h c1050h) {
        if (Log.isLoggable("ViewCompat", 3)) {
            Objects.toString(c1050h);
            view.getClass();
            view.getId();
        }
        if (Build.VERSION.SDK_INT >= 31) {
            return T.b(view, c1050h);
        }
        androidx.core.widget.p pVar = (androidx.core.widget.p) view.getTag(R.id.tag_on_receive_content_listener);
        InterfaceC1063u interfaceC1063u = e;
        if (pVar == null) {
            if (view instanceof InterfaceC1063u) {
                interfaceC1063u = (InterfaceC1063u) view;
            }
            return interfaceC1063u.a(c1050h);
        }
        C1050h c1050hA = androidx.core.widget.p.a(view, c1050h);
        if (c1050hA == null) {
            return null;
        }
        if (view instanceof InterfaceC1063u) {
            interfaceC1063u = (InterfaceC1063u) view;
        }
        return interfaceC1063u.a(c1050hA);
    }

    public static void l(int i, View view) {
        ArrayList arrayListF = f(view);
        for (int i2 = 0; i2 < arrayListF.size(); i2++) {
            if (((androidx.core.view.accessibility.d) arrayListF.get(i2)).a() == i) {
                arrayListF.remove(i2);
                return;
            }
        }
    }

    public static void m(View view, androidx.core.view.accessibility.d dVar, androidx.core.view.accessibility.n nVar) {
        androidx.core.view.accessibility.d dVar2 = new androidx.core.view.accessibility.d(null, dVar.b, null, nVar, dVar.c);
        View.AccessibilityDelegate accessibilityDelegateD = d(view);
        C1038b c1038b = accessibilityDelegateD == null ? null : accessibilityDelegateD instanceof C1036a ? ((C1036a) accessibilityDelegateD).a : new C1038b(accessibilityDelegateD);
        if (c1038b == null) {
            c1038b = new C1038b();
        }
        o(view, c1038b);
        l(dVar2.a(), view);
        f(view).add(dVar2);
        i(0, view);
    }

    public static void n(View view, Context context, int[] iArr, AttributeSet attributeSet, TypedArray typedArray, int i) {
        if (Build.VERSION.SDK_INT >= 29) {
            Q.b(view, context, iArr, attributeSet, typedArray, i, 0);
        }
    }

    public static void o(View view, C1038b c1038b) {
        if (c1038b == null && (d(view) instanceof C1036a)) {
            c1038b = new C1038b();
        }
        if (view.getImportantForAccessibility() == 0) {
            view.setImportantForAccessibility(1);
        }
        view.setAccessibilityDelegate(c1038b == null ? null : c1038b.b);
    }

    public static void p(View view, boolean z) {
        new G(R.id.tag_accessibility_heading, Boolean.class, 0, 28, 3).g(view, Boolean.valueOf(z));
    }

    public static void q(View view, CharSequence charSequence) {
        new G(R.id.tag_accessibility_pane_title, CharSequence.class, 8, 28, 1).g(view, charSequence);
        H h = f;
        if (charSequence == null) {
            h.a.remove(view);
            view.removeOnAttachStateChangeListener(h);
            view.getViewTreeObserver().removeOnGlobalLayoutListener(h);
        } else {
            h.a.put(view, Boolean.valueOf(view.isShown() && view.getWindowVisibility() == 0));
            view.addOnAttachStateChangeListener(h);
            if (view.isAttachedToWindow()) {
                view.getViewTreeObserver().addOnGlobalLayoutListener(h);
            }
        }
    }

    public static void r(View view, AbstractC1047f0 abstractC1047f0) {
        if (Build.VERSION.SDK_INT >= 30) {
            view.setWindowInsetsAnimationCallback(abstractC1047f0 != null ? new j0(abstractC1047f0) : null);
            return;
        }
        PathInterpolator pathInterpolator = i0.e;
        View.OnApplyWindowInsetsListener viewOnApplyWindowInsetsListenerC1051h0 = abstractC1047f0 != null ? new ViewOnApplyWindowInsetsListenerC1051h0(view, abstractC1047f0) : null;
        view.setTag(R.id.tag_window_insets_animation_callback, viewOnApplyWindowInsetsListenerC1051h0);
        if (view.getTag(R.id.tag_compat_insets_dispatch) == null && view.getTag(R.id.tag_on_apply_window_listener) == null) {
            view.setOnApplyWindowInsetsListener(viewOnApplyWindowInsetsListenerC1051h0);
        }
    }
}
