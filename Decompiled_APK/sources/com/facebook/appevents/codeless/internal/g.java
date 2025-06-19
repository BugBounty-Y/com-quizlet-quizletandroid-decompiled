package com.facebook.appevents.codeless.internal;

import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.EditText;
import android.widget.TextView;
import com.facebook.internal.J;
import com.facebook.o;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class g {
    public static final g a = new g();
    public static WeakReference b = new WeakReference(null);
    public static Method c;

    public static final ArrayList a(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(g.class)) {
            return null;
        }
        try {
            ArrayList arrayList = new ArrayList();
            if (view instanceof ViewGroup) {
                int childCount = ((ViewGroup) view).getChildCount();
                for (int i = 0; i < childCount; i++) {
                    arrayList.add(((ViewGroup) view).getChildAt(i));
                }
            }
            return arrayList;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(g.class, th);
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x004f A[Catch: all -> 0x004d, TRY_LEAVE, TryCatch #2 {all -> 0x004d, blocks: (B:16:0x0027, B:19:0x0030, B:29:0x0046, B:34:0x004f, B:42:0x005f, B:40:0x005a, B:26:0x0040, B:23:0x003a), top: B:85:0x0027, outer: #1, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x005f A[Catch: all -> 0x004d, TRY_LEAVE, TryCatch #2 {all -> 0x004d, blocks: (B:16:0x0027, B:19:0x0030, B:29:0x0046, B:34:0x004f, B:42:0x005f, B:40:0x005a, B:26:0x0040, B:23:0x003a), top: B:85:0x0027, outer: #1, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0087 A[PHI: r3
  0x0087: PHI (r3v15 int) = (r3v14 int), (r3v16 int) binds: [B:49:0x0073, B:54:0x0080] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int b(android.view.View r8) {
        /*
            Method dump skipped, instructions count: 198
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.internal.g.b(android.view.View):int");
    }

    public static final JSONObject c(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(g.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            if (view.getClass().getName().equals("com.facebook.react.ReactRootView")) {
                b = new WeakReference(view);
            }
            JSONObject jSONObject = new JSONObject();
            try {
                m(view, jSONObject);
                JSONArray jSONArray = new JSONArray();
                ArrayList arrayListA = a(view);
                int size = arrayListA.size();
                for (int i = 0; i < size; i++) {
                    jSONArray.put(c((View) arrayListA.get(i)));
                }
                jSONObject.put("childviews", jSONArray);
                return jSONObject;
            } catch (JSONException e) {
                Log.e("com.facebook.appevents.codeless.internal.g", "Failed to create JSONObject for view.", e);
                return jSONObject;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(g.class, th);
            return null;
        }
    }

    public static final View.OnClickListener e(View view) {
        Field declaredField;
        if (com.facebook.internal.instrument.crashshield.a.b(g.class)) {
            return null;
        }
        try {
            Field declaredField2 = Class.forName("android.view.View").getDeclaredField("mListenerInfo");
            if (declaredField2 != null) {
                declaredField2.setAccessible(true);
            }
            Object obj = declaredField2.get(view);
            if (obj == null || (declaredField = Class.forName("android.view.View$ListenerInfo").getDeclaredField("mOnClickListener")) == null) {
                return null;
            }
            declaredField.setAccessible(true);
            Object obj2 = declaredField.get(obj);
            Intrinsics.e(obj2, "null cannot be cast to non-null type android.view.View.OnClickListener");
            return (View.OnClickListener) obj2;
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchFieldException unused) {
            return null;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(g.class, th);
            return null;
        }
    }

    public static final View.OnTouchListener f(View view) {
        Field declaredField;
        try {
            if (!com.facebook.internal.instrument.crashshield.a.b(g.class)) {
                try {
                    Field declaredField2 = Class.forName("android.view.View").getDeclaredField("mListenerInfo");
                    if (declaredField2 != null) {
                        declaredField2.setAccessible(true);
                    }
                    Object obj = declaredField2.get(view);
                    if (obj != null && (declaredField = Class.forName("android.view.View$ListenerInfo").getDeclaredField("mOnTouchListener")) != null) {
                        declaredField.setAccessible(true);
                        Object obj2 = declaredField.get(obj);
                        Intrinsics.e(obj2, "null cannot be cast to non-null type android.view.View.OnTouchListener");
                        return (View.OnTouchListener) obj2;
                    }
                } catch (ClassNotFoundException unused) {
                    o oVar = o.a;
                } catch (IllegalAccessException unused2) {
                    o oVar2 = o.a;
                } catch (NoSuchFieldException unused3) {
                    o oVar3 = o.a;
                }
            }
            return null;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(g.class, th);
            return null;
        }
    }

    public static final String g(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(g.class)) {
            return null;
        }
        try {
            CharSequence hint = view instanceof EditText ? ((EditText) view).getHint() : view instanceof TextView ? ((TextView) view).getHint() : null;
            if (hint == null) {
                return "";
            }
            String string = hint.toString();
            return string == null ? "" : string;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(g.class, th);
            return null;
        }
    }

    public static final ViewGroup h(View view) {
        if (!com.facebook.internal.instrument.crashshield.a.b(g.class)) {
            try {
                ViewParent parent = view.getParent();
                if (parent instanceof ViewGroup) {
                    return (ViewGroup) parent;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(g.class, th);
                return null;
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x00fe  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.String i(android.view.View r7) {
        /*
            Method dump skipped, instructions count: 272
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.internal.g.i(android.view.View):java.lang.String");
    }

    public static final void m(View view, JSONObject json) {
        if (com.facebook.internal.instrument.crashshield.a.b(g.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            Intrinsics.checkNotNullParameter(json, "json");
            try {
                String strI = i(view);
                String strG = g(view);
                Object tag = view.getTag();
                CharSequence contentDescription = view.getContentDescription();
                json.put("classname", view.getClass().getCanonicalName());
                json.put("classtypebitmask", b(view));
                json.put("id", view.getId());
                if (f.b(view)) {
                    json.put("text", "");
                    json.put("is_user_input", true);
                } else {
                    json.put("text", J.e(J.O(strI)));
                }
                json.put("hint", J.e(J.O(strG)));
                if (tag != null) {
                    json.put("tag", J.e(J.O(tag.toString())));
                }
                if (contentDescription != null) {
                    json.put(OTUXParamsKeys.OT_UX_DESCRIPTION, J.e(J.O(contentDescription.toString())));
                }
                json.put("dimension", a.d(view));
            } catch (JSONException unused) {
                o oVar = o.a;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(g.class, th);
        }
    }

    public final JSONObject d(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            JSONObject jSONObject = new JSONObject();
            try {
                jSONObject.put("top", view.getTop());
                jSONObject.put("left", view.getLeft());
                jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, view.getWidth());
                jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, view.getHeight());
                jSONObject.put("scrollx", view.getScrollX());
                jSONObject.put("scrolly", view.getScrollY());
                jSONObject.put("visibility", view.getVisibility());
                return jSONObject;
            } catch (JSONException e) {
                Log.e("com.facebook.appevents.codeless.internal.g", "Failed to create JSONObject for dimension.", e);
                return jSONObject;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final View j(View view, float[] fArr) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                k();
                Method method = c;
                if (method != null && view != null) {
                    try {
                        Object objInvoke = method.invoke(null, fArr, view);
                        Intrinsics.e(objInvoke, "null cannot be cast to non-null type android.view.View");
                        View view2 = (View) objInvoke;
                        if (view2.getId() > 0) {
                            Object parent = view2.getParent();
                            Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                            return (View) parent;
                        }
                    } catch (IllegalAccessException unused) {
                        o oVar = o.a;
                    } catch (InvocationTargetException unused2) {
                        o oVar2 = o.a;
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final void k() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            if (c != null) {
                return;
            }
            try {
                Method declaredMethod = Class.forName("com.facebook.react.uimanager.TouchTargetHelper").getDeclaredMethod("findTouchTargetView", float[].class, ViewGroup.class);
                c = declaredMethod;
                if (declaredMethod == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                declaredMethod.setAccessible(true);
            } catch (ClassNotFoundException unused) {
                o oVar = o.a;
            } catch (NoSuchMethodException unused2) {
                o oVar2 = o.a;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final boolean l(View view, View view2) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Intrinsics.checkNotNullParameter(view, "view");
                if (view.getClass().getName().equals("com.facebook.react.views.view.ReactViewGroup")) {
                    float[] fArr = null;
                    if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                        try {
                            view.getLocationOnScreen(new int[2]);
                            fArr = new float[]{r2[0], r2[1]};
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(this, th);
                        }
                    }
                    View viewJ = j(view2, fArr);
                    if (viewJ != null) {
                        if (viewJ.getId() == view.getId()) {
                            return true;
                        }
                    }
                    return false;
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(this, th2);
                return false;
            }
        }
        return false;
    }
}
